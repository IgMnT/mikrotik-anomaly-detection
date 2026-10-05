#!/usr/bin/env python3
"""
=============================================================================
models.py — Detectores de anomalia com interface única (GPU quando possível)
=============================================================================
Todos os detectores seguem a mesma convenção:
    fit(X)            treina sobre tráfego considerado normal
    score(X)          escore de anomalia: QUANTO MAIOR, MAIS ANÔMALO
    calibrate(Xcal,q) fixa o limiar no percentil q dos escores de treino
                      (sem olhar o ground truth); DBSCAN usa o próprio eps
    predict(X)        1 = anomalia, 0 = normal

Backend (device="auto"): usa GPU se a biblioteca estiver instalada.
    Isolation Forest   cuml.ensemble.IsolationForest (cuML >= 26.08) | sklearn
    K-Means            cuml.cluster.KMeans                           | sklearn
    DBSCAN             cuml.cluster.DBSCAN + vizinho mais próximo    | sklearn
    LOF                kNN do cuML + fórmula do LOF em CuPy          | sklearn
    One-Class SVM      Nystroem + SGDOneClassSVM (CPU, linear)  ou ThunderSVM

Persistência: os detectores são serializáveis com joblib. Índices de vizinhos
e arrays de GPU não são gravados; são reconstruídos no primeiro uso após o
carregamento (a partir das matrizes guardadas em NumPy).
=============================================================================
"""
import time
import numpy as np

# ---------------------------------------------------------------- backends
try:
    import cupy as cp
    HAS_CUPY = True
except Exception:
    cp, HAS_CUPY = None, False
try:
    import cuml  # noqa: F401
    HAS_CUML = True
except Exception:
    HAS_CUML = False
try:
    from cuml.ensemble import IsolationForest as _cuIF  # cuML >= 26.08
    HAS_CUML_IF = True
except Exception:
    _cuIF, HAS_CUML_IF = None, False
try:
    from thundersvm import OneClassSVM as _tsvmOCSVM
    HAS_THUNDERSVM = True
except Exception:
    _tsvmOCSVM, HAS_THUNDERSVM = None, False

from sklearn.ensemble import IsolationForest as _skIF
from sklearn.cluster import KMeans as _skKMeans, DBSCAN as _skDBSCAN
from sklearn.neighbors import NearestNeighbors as _skNN, LocalOutlierFactor as _skLOF
from sklearn.kernel_approximation import Nystroem
from sklearn.linear_model import SGDOneClassSVM
from sklearn.pipeline import make_pipeline


def gpu_available():
    return HAS_CUML and HAS_CUPY


def backend_report():
    return {"cuml": HAS_CUML, "cupy": HAS_CUPY, "cuml_isolation_forest": HAS_CUML_IF,
            "thundersvm": HAS_THUNDERSVM}


def _use_gpu(device):
    if device == "cpu":
        return False
    if device == "gpu" and not gpu_available():
        raise RuntimeError("device='gpu' pedido, mas cuML/CuPy não estão instalados")
    return gpu_available()


def _to_np(a):
    if HAS_CUPY and isinstance(a, cp.ndarray):
        return cp.asnumpy(a)
    if hasattr(a, "to_numpy"):          # cudf / pandas
        return a.to_numpy()
    return np.asarray(a)


def _subsample(X, n, seed):
    if n is None or X.shape[0] <= n:
        return X
    idx = np.random.default_rng(seed).choice(X.shape[0], n, replace=False)
    return X[np.sort(idx)]


def _batched(fn, X, batch=200_000):
    return np.concatenate([fn(X[i:i + batch]) for i in range(0, X.shape[0], batch)])


# =============================================================================
class Detector:
    name = "base"
    uses_eps = False

    def __init__(self, device="auto", seed=0, max_fit=None):
        self.device = device
        self.seed = seed
        self.max_fit = max_fit
        self.threshold_ = None
        self.fit_time_ = None
        self.n_fit_ = None
        self.backend_ = None

    def fit(self, X):
        Xf = _subsample(np.ascontiguousarray(X, dtype=np.float32), self.max_fit, self.seed)
        self.n_fit_ = Xf.shape[0]
        t = time.perf_counter()
        self._fit(Xf)
        self.fit_time_ = time.perf_counter() - t
        return self

    def calibrate(self, Xcal, q=99.5):
        """Limiar = percentil q dos escores no treino (fixado a priori)."""
        if self.uses_eps:
            return self
        self.threshold_ = float(np.percentile(self.score(Xcal), q))
        return self

    def score(self, X):
        return _batched(self._score, np.ascontiguousarray(X, dtype=np.float32))

    def predict(self, X, scores=None):
        s = self.score(X) if scores is None else scores
        return (s > self.threshold_).astype(np.int8)

    def describe(self):
        return f"{self.name}[{self.backend_}] n_fit={self.n_fit_:,}"


# =============================================================================
class IFDetector(Detector):
    name = "isolation_forest"

    def __init__(self, n_estimators=200, max_samples=256, **kw):
        super().__init__(**kw)
        self.n_estimators, self.max_samples = n_estimators, max_samples

    def _fit(self, X):
        if _use_gpu(self.device) and HAS_CUML_IF:
            self.backend_ = "cuml"
            self.model_ = _cuIF(n_estimators=self.n_estimators,
                                max_samples=self.max_samples, random_state=self.seed)
        else:
            self.backend_ = "sklearn"
            self.model_ = _skIF(n_estimators=self.n_estimators,
                                max_samples=self.max_samples,
                                random_state=self.seed, n_jobs=-1)
        self.model_.fit(X)

    def _score(self, X):
        # convenção sklearn: score_samples menor = mais anômalo -> inverter
        return -_to_np(self.model_.score_samples(X)).astype(np.float64)


# =============================================================================
class KMeansDetector(Detector):
    """Escore = distância ao centroide mais próximo."""
    name = "kmeans"

    def __init__(self, n_clusters=8, **kw):
        super().__init__(**kw)
        self.n_clusters = n_clusters

    def _fit(self, X):
        if _use_gpu(self.device):
            from cuml.cluster import KMeans
            self.backend_ = "cuml"
            m = KMeans(n_clusters=self.n_clusters, random_state=self.seed)
        else:
            self.backend_ = "sklearn"
            m = _skKMeans(n_clusters=self.n_clusters, random_state=self.seed, n_init=3)
        m.fit(X)
        self.centers_ = _to_np(m.cluster_centers_).astype(np.float32)

    def _score(self, X):
        if self.backend_ == "cuml" and HAS_CUPY:
            Xg, C = cp.asarray(X), cp.asarray(self.centers_)
            d = ((Xg ** 2).sum(1, keepdims=True) - 2 * Xg @ C.T + (C ** 2).sum(1))
            return cp.asnumpy(cp.sqrt(cp.maximum(d.min(1), 0))).astype(np.float64)
        C = self.centers_
        d = (X ** 2).sum(1, keepdims=True) - 2 * X @ C.T + (C ** 2).sum(1)
        return np.sqrt(np.maximum(d.min(1), 0)).astype(np.float64)


# =============================================================================
class _NNIndex:
    """Busca de vizinhos: cuML (GPU, força bruta) ou sklearn (CPU).
    Não é serializado; reconstruído a partir de X quando necessário."""

    def __init__(self, X, gpu):
        self.gpu = gpu
        if gpu:
            from cuml.neighbors import NearestNeighbors
            self.nn = NearestNeighbors()
        else:
            self.nn = _skNN(n_jobs=-1)
        self.nn.fit(X)

    def kneighbors(self, X, k):
        d, i = self.nn.kneighbors(X, n_neighbors=k)
        return _to_np(d).astype(np.float32), _to_np(i).astype(np.int64)


class _NeedsIndex:
    def __getstate__(self):
        st = self.__dict__.copy()
        st.pop("_index", None)
        return st

    def _get_index(self, X):
        if getattr(self, "_index", None) is None:
            self._index = _NNIndex(X, self.backend_ == "gpu")
        return self._index


# =============================================================================
class LOFDetector(_NeedsIndex, Detector):
    """LOF em modo novidade (treina no normal, pontua registros novos).
    GPU: kNN do cuML + cálculo do LOF vetorizado (CuPy/NumPy), mesma fórmula
    do scikit-learn. CPU: sklearn LocalOutlierFactor(novelty=True)."""
    name = "lof"

    def __init__(self, n_neighbors=20, **kw):
        kw.setdefault("max_fit", 500_000)
        super().__init__(**kw)
        self.k = n_neighbors

    def _fit(self, X):
        if _use_gpu(self.device) or self.device == "manual":
            self.backend_ = "gpu" if self.device != "manual" else "manual_cpu"
            self.X_ = X
            idx = self._get_index(X)
            d, i = idx.kneighbors(X, self.k + 1)       # 1º vizinho = o próprio ponto
            d, i = d[:, 1:], i[:, 1:]
            self.kdist_ = d[:, -1]                     # distância ao k-ésimo vizinho
            reach = np.maximum(d, self.kdist_[i])
            self.lrd_ = 1.0 / (reach.mean(1) + 1e-10)
        else:
            self.backend_ = "sklearn"
            self.model_ = _skLOF(n_neighbors=self.k, novelty=True, n_jobs=-1).fit(X)

    def _score(self, X):
        if self.backend_ == "sklearn":
            return -self.model_.score_samples(X).astype(np.float64)
        d, i = self._get_index(self.X_).kneighbors(X, self.k)
        reach = np.maximum(d, self.kdist_[i])
        lrd_x = 1.0 / (reach.mean(1) + 1e-10)
        return (self.lrd_[i].mean(1) / lrd_x).astype(np.float64)


def validate_lof(X, n=20_000, k=20, seed=0):
    """Compara a implementação manual (a mesma usada na GPU) com o sklearn,
    rodando ambas na CPU. Retorna a correlação e o erro relativo máximo."""
    X = _subsample(np.ascontiguousarray(X, dtype=np.float32), n, seed)
    half = X.shape[0] // 2
    A, B = X[:half], X[half:]
    man = LOFDetector(n_neighbors=k, device="manual").fit(A)
    ref = _skLOF(n_neighbors=k, novelty=True).fit(A)
    s_man, s_ref = man.score(B), -ref.score_samples(B)
    corr = float(np.corrcoef(s_man, s_ref)[0, 1])
    rel = float(np.max(np.abs(s_man - s_ref) / np.maximum(np.abs(s_ref), 1e-9)))
    return corr, rel


# =============================================================================
class DBSCANDetector(_NeedsIndex, Detector):
    """Treina o DBSCAN numa subamostra; um registro novo é anômalo se estiver
    a mais de eps de qualquer ponto central (core point).
    Escore = distância ao ponto central mais próximo; limiar = eps.
    eps: se None, estimado pelo percentil eps_q das distâncias ao
    min_samples-ésimo vizinho (versão automática do gráfico de k-distâncias)."""
    name = "dbscan"
    uses_eps = True

    def __init__(self, eps=None, min_samples=20, eps_q=95.0, **kw):
        kw.setdefault("max_fit", 200_000)
        super().__init__(**kw)
        self.eps, self.min_samples, self.eps_q = eps, min_samples, eps_q

    def _fit(self, X):
        gpu = _use_gpu(self.device)
        if self.eps is None:
            probe = _subsample(X, 50_000, self.seed)
            d, _ = _NNIndex(probe, gpu).kneighbors(probe, self.min_samples + 1)
            self.eps = float(np.percentile(d[:, -1], self.eps_q))
        if gpu:
            from cuml.cluster import DBSCAN
            self.backend_ = "gpu"
            m = DBSCAN(eps=self.eps, min_samples=self.min_samples,
                       calc_core_sample_indices=True)
        else:
            self.backend_ = "cpu"
            m = _skDBSCAN(eps=self.eps, min_samples=self.min_samples, n_jobs=-1)
        m.fit(X)
        core = _to_np(m.core_sample_indices_)
        self.cores_ = X[core] if len(core) else X[:1]
        self.threshold_ = self.eps
        self.n_cores_ = len(core)

    def _score(self, X):
        d, _ = self._get_index(self.cores_).kneighbors(X, 1)
        return d[:, 0].astype(np.float64)

    def describe(self):
        return (f"{self.name}[{self.backend_}] n_fit={self.n_fit_:,} "
                f"eps={self.eps:.3f} cores={self.n_cores_:,}")


# =============================================================================
class OCSVMDetector(Detector):
    """impl="nystroem": aproximação de Nyström do núcleo RBF + SGDOneClassSVM
    (CPU, custo linear no nº de amostras).
    impl="thundersvm": One-Class SVM com núcleo RBF na GPU (ThunderSVM),
    sobre subamostra (custo superlinear)."""
    name = "ocsvm"

    def __init__(self, nu=0.01, n_components=300, gamma=None, impl="nystroem", **kw):
        if impl == "thundersvm":
            kw.setdefault("max_fit", 200_000)
        super().__init__(**kw)
        self.nu, self.n_components, self.gamma, self.impl = nu, n_components, gamma, impl

    def _fit(self, X):
        g = self.gamma if self.gamma is not None else 1.0 / X.shape[1]
        if self.impl == "thundersvm":
            if not HAS_THUNDERSVM:
                raise RuntimeError("impl='thundersvm' pedido, mas não está instalado")
            self.backend_ = "thundersvm"
            self.model_ = _tsvmOCSVM(kernel="rbf", nu=self.nu, gamma=g)
        else:
            self.backend_ = "nystroem+sgd"
            self.model_ = make_pipeline(
                Nystroem(gamma=g, n_components=self.n_components, random_state=self.seed),
                SGDOneClassSVM(nu=self.nu, random_state=self.seed))
        self.model_.fit(X)

    def _score(self, X):
        return -np.asarray(self.model_.decision_function(X), dtype=np.float64).ravel()


# =============================================================================
MODEL_NAMES = ("isolation_forest", "lof", "ocsvm", "dbscan", "kmeans")
DETERMINISTIC = {"lof", "dbscan"}


def make_detector(name, device="auto", seed=0, **params):
    cls = {"isolation_forest": IFDetector, "lof": LOFDetector, "ocsvm": OCSVMDetector,
           "dbscan": DBSCANDetector, "kmeans": KMeansDetector}[name]
    return cls(device=device, seed=seed, **params)


def ensemble_votes(preds):
    """preds: dict nome -> array 0/1. Retorna o número de votos por registro."""
    return np.sum(np.vstack(list(preds.values())), axis=0).astype(np.int8)
