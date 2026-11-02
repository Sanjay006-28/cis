"""
Research Evaluation: Feature Selection on Normalized Shares vs Raw Syscall Counts
--------------------------------------------------------------------------------
This module implements an executable experimental pipeline comparing:
1. Count-Based Feature Selection: Selecting features on raw syscall counts, then training on shares.
2. Share-Based Feature Selection: Selecting features directly on normalized syscall shares, then training on shares.

Both approaches are evaluated using comparable 5-fold cluster-held-out cross-validation
on the authentic CICMalDroid2020 dataset (feature_vectors_syscallsbinders_frequency_5_Cat.csv).
Existing operational models and benchmarks are strictly preserved.
"""

import os
import sys
import json
import time
import warnings
from pathlib import Path
import numpy as np
import pandas as pd
from scipy.stats import binomtest
from sklearn.cluster import KMeans
from sklearn.feature_selection import mutual_info_classif
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GroupKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
)
import xgboost as xgb

warnings.filterwarnings("ignore")

SEED = 42
CSV_PATH = "feature_vectors_syscallsbinders_frequency_5_Cat.csv"
OUT_DIR = "dynamic_outputs_v2"
TOP_K = 50
IG_CANDIDATES = 100
N_CLUSTERS = 200

SYSCALLS = [
    '__arm_nr_cacheflush', '__arm_nr_set_tls', '_llseek', '_newselect', 'accept', 'access', 'bind',
    'brk', 'capset', 'chdir', 'chmod', 'chown32', 'clock_getres', 'clock_gettime', 'clone', 'close',
    'connect', 'dup', 'dup2', 'epoll_create', 'epoll_ctl', 'epoll_wait', 'eventfd2', 'execve', 'exit',
    'exit_group', 'faccessat', 'fchmod', 'fchown32', 'fcntl', 'fcntl64', 'fdatasync', 'flock', 'fork',
    'fstat64', 'fstatfs64', 'fsync', 'ftruncate', 'ftruncate64', 'futex', 'getcwd', 'getdents64',
    'getegid32', 'geteuid32', 'getgid32', 'getgroups32', 'getpeername', 'getpgid', 'getpid', 'getppid',
    'getpriority', 'getresgid32', 'getresuid32', 'getrusage', 'getsockname', 'getsockopt', 'gettid',
    'gettimeofday', 'getuid32', 'inotify_add_watch', 'inotify_init', 'inotify_rm_watch', 'ioctl',
    'lgetxattr', 'link', 'listen', 'lseek', 'lstat64', 'madvise', 'mkdir', 'mknod', 'mlock', 'mmap2',
    'mount', 'mprotect', 'mremap', 'msync', 'munlock', 'munmap', 'nanosleep', 'open', 'pipe', 'pipe2',
    'poll', 'prctl', 'pread64', 'ptrace', 'pwrite64', 'read', 'readlink', 'recvfrom', 'recvmsg', 'rename',
    'rmdir', 'rt_sigprocmask', 'rt_sigtimedwait', 'sched_get_priority_max', 'sched_get_priority_min',
    'sched_getparam', 'sched_getscheduler', 'sched_setaffinity', 'sched_setscheduler', 'sched_yield',
    'sendmsg', 'sendto', 'setgid32', 'setgroups32', 'setitimer', 'setpgid', 'setpriority', 'setresgid32',
    'setresuid32', 'setrlimit', 'setsid', 'setsockopt', 'setuid32', 'shutdown', 'sigaction', 'sigaltstack',
    'sigprocmask', 'sigsuspend', 'socket', 'socketpair', 'stat64', 'statfs64', 'symlink', 'sysinfo',
    'timer_create', 'timer_settime', 'truncate', 'ugetrlimit', 'umask', 'uname', 'unlink', 'utimes',
    'vfork', 'wait4', 'write', 'writev'
]


def to_shares(frame: pd.DataFrame) -> pd.DataFrame:
    """Normalize system call counts into frequency shares summing to 1."""
    return frame.div(frame.sum(axis=1).replace(0, 1), axis=0)


def select_features(Xtr: pd.DataFrame, ytr: pd.Series, k: int = TOP_K, seed: int = SEED):
    """Two-stage feature selection:
    1. Information Gain (mutual_info_classif) -> top IG_CANDIDATES
    2. ExtraTreesClassifier (Gini importance) -> top k
    """
    mi = pd.Series(
        mutual_info_classif(Xtr, ytr, discrete_features=False, random_state=seed),
        index=Xtr.columns
    )
    cand = mi.sort_values(ascending=False).head(max(IG_CANDIDATES, k)).index.tolist()
    et = ExtraTreesClassifier(n_estimators=300, random_state=seed, n_jobs=-1).fit(Xtr[cand], ytr)
    gini = pd.Series(et.feature_importances_, index=cand).sort_values(ascending=False)
    return gini.head(k).index.tolist(), gini


def compute_metrics(y_true, y_prob, threshold=0.5):
    y_pred = (y_prob >= threshold).astype(int)
    return {
        "Accuracy": float(accuracy_score(y_true, y_pred)),
        "Precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "Recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "Specificity": float(recall_score(y_true, y_pred, pos_label=0, zero_division=0)),
        "F1": float(f1_score(y_true, y_pred, zero_division=0)),
        "ROC-AUC": float(roc_auc_score(y_true, y_prob)),
    }


def run_experiment(verbose: bool = True):
    """Execute the full comparative experiment on the CICMalDroid dataset."""
    csv_file = Path(CSV_PATH)
    if not csv_file.is_file():
        raise FileNotFoundError(f"Dataset {CSV_PATH} not found.")

    if verbose:
        print(f"Loading {CSV_PATH} ...")
    df = pd.read_csv(csv_file)
    tmp = df[SYSCALLS].copy()
    tmp["y"] = (df["Class"] != 5).astype(int)
    conflict = tmp.groupby(SYSCALLS)["y"].transform("nunique") > 1
    tmp = tmp[~conflict].drop_duplicates(subset=SYSCALLS).reset_index(drop=True)
    X = tmp[SYSCALLS]
    y = tmp["y"]

    if verbose:
        print(f"Samples: {len(X)} ({y.sum()} malware, {(y == 0).sum()} benign)")
        print(f"Computing {N_CLUSTERS} KMeans behavioral clusters for cluster-held-out splits ...")

    Zall = StandardScaler().fit_transform(np.log1p(X.values))
    groups = KMeans(N_CLUSTERS, n_init=3, random_state=SEED).fit_predict(Zall)

    gkf = GroupKFold(n_splits=5)
    folds = list(gkf.split(X, y, groups))

    results_count_sel = []
    results_share_sel = []
    all_oof_count = np.zeros(len(X))
    all_oof_share = np.zeros(len(X))
    top_features_count_per_fold = []
    top_features_share_per_fold = []

    for fold_idx, (tr_idx, te_idx) in enumerate(folds, 1):
        t0 = time.time()
        X_tr, y_tr = X.iloc[tr_idx], y.iloc[tr_idx]
        X_te, y_te = X.iloc[te_idx], y.iloc[te_idx]
        S_tr = to_shares(X_tr)
        S_te = to_shares(X_te)

        # 1. Condition A: Feature selection on raw counts
        top_count, _ = select_features(X_tr, y_tr, k=TOP_K, seed=SEED + fold_idx)
        top_features_count_per_fold.append(top_count)
        scale_pos = (y_tr == 0).sum() / (y_tr == 1).sum()
        xgb_count = xgb.XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1, eval_metric="logloss",
            scale_pos_weight=scale_pos, random_state=SEED, n_jobs=-1
        ).fit(S_tr[top_count], y_tr)
        p_count = xgb_count.predict_proba(S_te[top_count])[:, 1]
        all_oof_count[te_idx] = p_count
        m_count = compute_metrics(y_te, p_count)
        results_count_sel.append(m_count)

        # 2. Condition B: Feature selection directly on normalized shares
        top_share, _ = select_features(S_tr, y_tr, k=TOP_K, seed=SEED + fold_idx)
        top_features_share_per_fold.append(top_share)
        xgb_share = xgb.XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1, eval_metric="logloss",
            scale_pos_weight=scale_pos, random_state=SEED, n_jobs=-1
        ).fit(S_tr[top_share], y_tr)
        p_share = xgb_share.predict_proba(S_te[top_share])[:, 1]
        all_oof_share[te_idx] = p_share
        m_share = compute_metrics(y_te, p_share)
        results_share_sel.append(m_share)

        if verbose:
            print(f"Fold {fold_idx}/5 finished in {time.time()-t0:.1f}s | "
                  f"Count-Sel F1: {m_count['F1']:.4f} | Share-Sel F1: {m_share['F1']:.4f}")

    # Aggregate cross-validation metrics
    df_count = pd.DataFrame(results_count_sel)
    df_share = pd.DataFrame(results_share_sel)

    # McNemar test comparing out-of-fold classifications
    c_count = ((all_oof_count >= 0.5).astype(int) == y.values)
    c_share = ((all_oof_share >= 0.5).astype(int) == y.values)
    b = int((c_count & ~c_share).sum())
    c = int((~c_count & c_share).sum())
    p_val = float(binomtest(min(b, c), b + c, 0.5).pvalue if b + c > 0 else 1.0)

    # Global feature overlap
    global_top_count = set(top_features_count_per_fold[0])
    global_top_share = set(top_features_share_per_fold[0])
    jaccard = len(global_top_count & global_top_share) / len(global_top_count | global_top_share)

    experiment_summary = {
        "status": "completed",
        "dataset": CSV_PATH,
        "n_samples": len(X),
        "n_malware": int(y.sum()),
        "n_benign": int((y == 0).sum()),
        "k_features": TOP_K,
        "n_folds": 5,
        "evaluation_strategy": "cluster_held_out (GroupKFold on KMeans clusters)",
        "condition_a_count_based_selection": {
            "description": "Information Gain + Extra Trees on raw counts; XGBoost trained/tested on shares",
            "mean_accuracy": float(df_count["Accuracy"].mean()),
            "std_accuracy": float(df_count["Accuracy"].std()),
            "mean_f1": float(df_count["F1"].mean()),
            "std_f1": float(df_count["F1"].std()),
            "mean_recall": float(df_count["Recall"].mean()),
            "std_recall": float(df_count["Recall"].std()),
            "mean_specificity": float(df_count["Specificity"].mean()),
            "std_specificity": float(df_count["Specificity"].std()),
            "mean_roc_auc": float(df_count["ROC-AUC"].mean()),
            "std_roc_auc": float(df_count["ROC-AUC"].std()),
        },
        "condition_b_share_based_selection": {
            "description": "Information Gain + Extra Trees directly on shares; XGBoost trained/tested on shares",
            "mean_accuracy": float(df_share["Accuracy"].mean()),
            "std_accuracy": float(df_share["Accuracy"].std()),
            "mean_f1": float(df_share["F1"].mean()),
            "std_f1": float(df_share["F1"].std()),
            "mean_recall": float(df_share["Recall"].mean()),
            "std_recall": float(df_share["Recall"].std()),
            "mean_specificity": float(df_share["Specificity"].mean()),
            "std_specificity": float(df_share["Specificity"].std()),
            "mean_roc_auc": float(df_share["ROC-AUC"].mean()),
            "std_roc_auc": float(df_share["ROC-AUC"].std()),
        },
        "statistical_comparison": {
            "mcnemar_b": b,
            "mcnemar_c": c,
            "p_value": p_val,
            "statistically_significant_at_05": p_val < 0.05,
            "feature_set_jaccard_similarity": float(jaccard),
            "common_features_count": len(global_top_count & global_top_share),
        },
    }

    out_json = Path(OUT_DIR) / "feature_selection_experiment_results.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(experiment_summary, f, indent=2)

    if verbose:
        print("\n" + "="*60)
        print("EXPERIMENT RESULTS: CLUSTER-HELD-OUT 5-FOLD CV")
        print("="*60)
        print(f"Condition A (Count Selection) -> F1: {df_count['F1'].mean():.4f} +/- {df_count['F1'].std():.4f} | "
              f"Acc: {df_count['Accuracy'].mean():.4f} | Specificity: {df_count['Specificity'].mean():.4f}")
        print(f"Condition B (Share Selection) -> F1: {df_share['F1'].mean():.4f} +/- {df_share['F1'].std():.4f} | "
              f"Acc: {df_share['Accuracy'].mean():.4f} | Specificity: {df_share['Specificity'].mean():.4f}")
        print(f"Feature overlap (Jaccard): {jaccard:.2%} ({len(global_top_count & global_top_share)}/50 shared)")
        print(f"McNemar p-value: {p_val:.4f} (Significant: {'YES' if p_val < 0.05 else 'NO'})")
        print(f"Results saved to {out_json}")

    return experiment_summary


if __name__ == "__main__":
    run_experiment(verbose=True)
