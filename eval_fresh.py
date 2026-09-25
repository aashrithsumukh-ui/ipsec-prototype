import numpy as np
import pandas as pd
from sklearn.model_selection import LeaveOneGroupOut, GroupKFold
from sklearn.metrics import accuracy_score, f1_score, classification_report
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier
from ipsecguard.classifier import TrafficClassifier
from ipsecguard.schema import FLOW_FEATURES

def main():
    df = pd.read_csv('dataset.csv')
    print(f"[Dataset] {len(df)} sessions, {df.config_id.nunique()} distinct tunnel configs")

    # 1. Standard fit_eval from classifier.py
    clf = TrafficClassifier()
    m = clf.fit_eval(df)
    print(f"[Standard Held-Out Config Split] accuracy={m['accuracy']:.4f}, f1={m['f1_macro']:.4f} (train={m['n_train']}, test={m['n_test']})")

    # 2. 4-Fold Grouped CV
    X = df[FLOW_FEATURES].values
    le = LabelEncoder()
    y = le.fit_transform(df['traffic_type'].values)
    groups = df['config_id'].values

    gkf = GroupKFold(n_splits=4)
    g_accs, g_f1s, g_yt, g_yp = [], [], [], []
    for i, (tr, te) in enumerate(gkf.split(X, y, groups), 1):
        mdl = XGBClassifier(
            n_estimators=400, max_depth=4, learning_rate=0.08,
            subsample=0.9, colsample_bytree=0.8, reg_lambda=2.0,
            eval_metric='mlogloss', tree_method='hist', random_state=7
        )
        mdl.fit(X[tr], y[tr])
        p = mdl.predict(X[te])
        a = accuracy_score(y[te], p)
        f = f1_score(y[te], p, average='macro')
        g_accs.append(a)
        g_f1s.append(f)
        g_yt += list(y[te])
        g_yp += list(p)
        print(f"  GroupKFold {i}: acc={a:.4f}, f1={f:.4f} (test_size={len(te)})")
    
    print(f"\n[4-Fold Grouped CV Result] accuracy={np.mean(g_accs):.4f} +/- {np.std(g_accs):.4f} (range: {np.min(g_accs):.4f} - {np.max(g_accs):.4f}), f1_macro={np.mean(g_f1s):.4f} +/- {np.std(g_f1s):.4f} (range: {np.min(g_f1s):.4f} - {np.max(g_f1s):.4f})")

    # 3. Leave-One-Configuration-Out CV (8 folds for 8 configs)
    logo = LeaveOneGroupOut()
    l_accs, l_f1s, l_yt, l_yp = [], [], [], []
    for i, (tr, te) in enumerate(logo.split(X, y, groups), 1):
        mdl = XGBClassifier(
            n_estimators=400, max_depth=4, learning_rate=0.08,
            subsample=0.9, colsample_bytree=0.8, reg_lambda=2.0,
            eval_metric='mlogloss', tree_method='hist', random_state=7
        )
        mdl.fit(X[tr], y[tr])
        p = mdl.predict(X[te])
        a = accuracy_score(y[te], p)
        f = f1_score(y[te], p, average='macro')
        l_accs.append(a)
        l_f1s.append(f)
        l_yt += list(y[te])
        l_yp += list(p)
        print(f"  Config {i}/8 held-out: acc={a:.4f}, f1={f:.4f} (test_size={len(te)})")

    print(f"\n[Leave-One-Configuration-Out Result] accuracy={np.mean(l_accs):.4f} +/- {np.std(l_accs):.4f} (range: {np.min(l_accs):.4f} - {np.max(l_accs):.4f}), f1_macro={np.mean(l_f1s):.4f} +/- {np.std(l_f1s):.4f} (range: {np.min(l_f1s):.4f} - {np.max(l_f1s):.4f})")
    
    print("\n[Per-Class Classification Report (4-Fold Grouped CV)]")
    print(classification_report(g_yt, g_yp, target_names=le.classes_, digits=4))

    print("\n[Per-Class Classification Report (Leave-One-Configuration-Out)]")
    print(classification_report(l_yt, l_yp, target_names=le.classes_, digits=4))

if __name__ == '__main__':
    main()
