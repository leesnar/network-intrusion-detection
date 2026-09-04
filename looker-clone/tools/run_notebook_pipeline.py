# -*- coding: utf-8 -*-
"""
run_notebook_pipeline.py — runs `Script Colab.ipynb` headlessly on the real data.

The notebook reads /content/Train_data.csv + /content/Test_data.csv in Colab and
exports 11 CSVs. This script reproduces cells 12-35 exactly (same RANDOM_STATE,
same encoders, same split, same models, same IsolationForest) against the local
copies of those files, and writes the same 11 CSVs to an export directory.

    python run_notebook_pipeline.py                     # defaults below
    python run_notebook_pipeline.py --data-dir <dir> --out <dir>

Then feed the result to the dashboard:

    python build_data.py --from-csv ../exports
"""

import argparse
import os
import time

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import (RandomForestClassifier, GradientBoostingClassifier,
                              IsolationForest)
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_DATA = os.path.abspath(os.path.join(ROOT, "..", ".."))   # "PROJECT MEI"
DEFAULT_OUT = os.path.join(ROOT, "exports")

RANDOM_STATE = 42


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default=DEFAULT_DATA,
                    help="folder holding Train_data.csv and Test_data.csv")
    ap.add_argument("--out", default=DEFAULT_OUT, help="export folder")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    # -- cell 3: load ------------------------------------------------------
    train = pd.read_csv(os.path.join(args.data_dir, "Train_data.csv"))
    test = pd.read_csv(os.path.join(args.data_dir, "Test_data.csv"))
    print("Train : %s rows x %s cols" % (f"{train.shape[0]:,}", train.shape[1]))
    print("Test  : %s rows x %s cols" % (f"{test.shape[0]:,}", test.shape[1]))

    # -- cell 12: encode categoricals on the train+test union --------------
    df, df_t = train.copy(), test.copy()
    categorical_cols = ["protocol_type", "service", "flag"]
    combined = pd.concat([df[categorical_cols], df_t[categorical_cols]])
    encoders = {}
    for col in categorical_cols:
        le = LabelEncoder()
        le.fit(combined[col])
        encoders[col] = le
        df[col] = le.transform(df[col])
        df_t[col] = le.transform(df_t[col])

    # -- cell 13: encode the target ---------------------------------------
    target_encoder = LabelEncoder()
    df["class"] = target_encoder.fit_transform(df["class"])
    print("Label mapping : %s" % dict(zip(target_encoder.classes_,
                                          target_encoder.transform(target_encoder.classes_))))

    # -- cell 14: split + one shared scaler --------------------------------
    X = df.drop("class", axis=1)
    y = df["class"]
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE)
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s = scaler.transform(X_val)
    X_full_s = scaler.transform(X)

    # -- cell 16: train the five models ------------------------------------
    model_defs = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=RANDOM_STATE),
        "Decision Tree": DecisionTreeClassifier(max_depth=10, random_state=RANDOM_STATE),
        "K-Nearest Neighbors": KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
        "Random Forest": RandomForestClassifier(n_estimators=200, random_state=RANDOM_STATE, n_jobs=-1),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, random_state=RANDOM_STATE),
    }
    records, trained = [], {}
    print("\n%-25s %7s %7s %7s %7s %6s" % ("Model", "Acc", "Prec", "Rec", "F1", "Time"))
    print("-" * 65)
    for name, mdl in model_defs.items():
        t0 = time.time()
        mdl.fit(X_train_s, y_train)
        t = time.time() - t0
        yp = mdl.predict(X_val_s)
        acc = accuracy_score(y_val, yp)
        prec = precision_score(y_val, yp)
        rec = recall_score(y_val, yp)
        f1 = f1_score(y_val, yp)
        records.append({"Model": name, "Accuracy": round(acc * 100, 2),
                        "Precision": round(prec * 100, 2), "Recall": round(rec * 100, 2),
                        "F1": round(f1 * 100, 2), "Time_s": round(t, 2)})
        trained[name] = mdl
        print("%-25s %6.2f%% %6.2f%% %6.2f%% %6.2f%% %5.1fs"
              % (name, acc * 100, prec * 100, rec * 100, f1 * 100, t))
    results = pd.DataFrame(records).sort_values("F1", ascending=False).reset_index(drop=True)

    # -- cell 20: RF feature importance ------------------------------------
    rf_model = trained["Random Forest"]
    importance = pd.DataFrame({
        "Feature": X.columns,
        "Importance": rf_model.feature_importances_,
    }).sort_values("Importance", ascending=False).reset_index(drop=True)

    # -- cell 22-24: IsolationForest, risk score, priority -----------------
    iso = IsolationForest(contamination=0.10, n_estimators=200, random_state=RANDOM_STATE)
    iso.fit(X_full_s)
    df["anomaly_pred"] = pd.Series(iso.predict(X_full_s)).map({1: 0, -1: 1}).values
    df["anomaly_score"] = iso.decision_function(X_full_s)

    min_s, max_s = df["anomaly_score"].min(), df["anomaly_score"].max()
    df["risk_score"] = ((max_s - df["anomaly_score"]) / (max_s - min_s)) * 100

    def threat_category(s):
        return ("Informational" if s < 25 else "Low" if s < 50
                else "Medium" if s < 75 else "Critical")

    def priority(s):
        return ("P4-Low" if s < 25 else "P3-Medium" if s < 50
                else "P2-High" if s < 75 else "P1-Critical")

    df["ThreatCategory"] = df["risk_score"].apply(threat_category)
    df["Priority"] = df["risk_score"].apply(priority)
    print("\nRisk score  min %.2f  max %.2f  mean %.2f"
          % (df["risk_score"].min(), df["risk_score"].max(), df["risk_score"].mean()))
    print(df["Priority"].value_counts().to_string())

    # -- cell 27-29: dashboard dataset, health index, RF predictions -------
    dashboard_dataset = train.copy()
    for col in ("risk_score", "ThreatCategory", "Priority", "anomaly_pred"):
        dashboard_dataset[col] = df[col].values

    security_df = df.copy()
    security_health_index = round(100 - security_df["risk_score"].mean(), 2)
    print("Security Health Index : %s" % security_health_index)

    rf_best = trained["Random Forest"]
    rf_proba = rf_best.predict_proba(X_val_s)
    prediction_df = pd.DataFrame({
        "Actual": y_val.values,
        "Prediction": rf_best.predict(X_val_s),
        "Probability": rf_proba.max(axis=1).round(4),
        "RiskScore_RF": ((1 - rf_proba[:, 1]) * 100).round(2),
    })
    prediction_df["RiskLevel_RF"] = prediction_df["RiskScore_RF"].apply(
        lambda s: "Low" if s < 30 else "Medium" if s < 70 else "High")

    # -- cell 31: top 100 highest risk records -----------------------------
    top_risk = (dashboard_dataset
                .sort_values("risk_score", ascending=False)
                .head(100)
                [["protocol_type", "service", "flag", "src_bytes", "dst_bytes",
                  "risk_score", "ThreatCategory", "Priority", "class"]]
                .reset_index(drop=True))

    # -- cell 32: export ---------------------------------------------------
    def out(name):
        return os.path.join(args.out, name)

    results.to_csv(out("model_performance.csv"), index=False)
    importance.to_csv(out("feature_importance.csv"), index=False)
    prediction_df.to_csv(out("network_prediction.csv"), index=False)
    security_df.to_csv(out("security_intelligence.csv"), index=False)
    dashboard_dataset.to_csv(out("dashboard_dataset.csv"), index=False)
    top_risk.to_csv(out("top_risk_records.csv"), index=False)

    rf_row = results[results["Model"] == "Random Forest"]
    dashboard_summary = pd.DataFrame([{
        "TotalTraffic": len(security_df),
        "AnomalyCount": int((security_df["anomaly_pred"] == 1).sum()),
        "NormalCount": int((security_df["anomaly_pred"] == 0).sum()),
        "CriticalThreatCount": int((security_df["Priority"] == "P1-Critical").sum()),
        "HighRiskCount": int((security_df["Priority"] == "P2-High").sum()),
        "SecurityHealthIndex": security_health_index,
        "AverageRiskScore": round(security_df["risk_score"].mean(), 2),
        "RF_Accuracy_pct": rf_row["Accuracy"].values[0],
        "RF_Precision_pct": rf_row["Precision"].values[0],
        "RF_Recall_pct": rf_row["Recall"].values[0],
        "RF_F1_pct": rf_row["F1"].values[0],
    }])
    dashboard_summary.to_csv(out("dashboard_summary.csv"), index=False)

    # -- cell 35: the four extra chart feeds -------------------------------
    num_cols = train.select_dtypes(include=np.number).columns
    y_bin = (train["class"] == "anomaly").astype(int)
    corr_label = train[num_cols].corrwith(y_bin).abs().nlargest(12)
    top12_cols = corr_label.index.tolist()

    # cell 10 only plotted this; the dashboard wants it as a table too
    (corr_label.reset_index()
     .set_axis(["Feature", "Correlation"], axis=1)
     .assign(Abs_Correlation=lambda d: d["Correlation"].abs().round(6))
     .to_csv(out("correlation_label.csv"), index=False))

    corr_matrix = train[top12_cols].corr().round(3)
    corr_long = (corr_matrix.reset_index()
                 .melt(id_vars="index", var_name="Feature_B", value_name="Correlation")
                 .rename(columns={"index": "Feature_A"}))
    corr_long["Abs_Correlation"] = corr_long["Correlation"].abs().round(3)
    corr_long.to_csv(out("correlation_matrix.csv"), index=False)

    feat_model_rows = []
    for name, mdl in trained.items():
        if hasattr(mdl, "feature_importances_"):
            for feat, imp in zip(X.columns, mdl.feature_importances_):
                feat_model_rows.append({"Model": name, "Feature": feat,
                                        "Importance": round(float(imp), 4)})
    feat_model_df = pd.DataFrame(feat_model_rows)
    top10_feats = (feat_model_df[feat_model_df["Model"] == "Random Forest"]
                   .nlargest(10, "Importance")["Feature"].tolist())
    feat_model_df[feat_model_df["Feature"].isin(top10_feats)].to_csv(
        out("feature_model_importance.csv"), index=False)

    service_stats = (train.groupby("service")
                     .agg(Total=("class", "count"),
                          Anomaly=("class", lambda x: (x == "anomaly").sum()),
                          Normal=("class", lambda x: (x == "normal").sum()))
                     .reset_index())
    service_stats["Anomaly_Rate"] = (service_stats["Anomaly"] / service_stats["Total"] * 100).round(2)
    service_stats.nlargest(15, "Total").to_csv(out("service_stats.csv"), index=False)

    bins = list(range(0, 105, 5))
    labels = ["[%d,%d)" % (i, i + 5) for i in bins[:-1]]
    bucket_col = pd.cut(security_df["risk_score"], bins=bins, labels=labels, right=False)
    risk_bucket = bucket_col.value_counts().sort_index().reset_index()
    risk_bucket.columns = ["Risk_Bucket", "Record_Count"]
    risk_bucket["Bucket_Start"] = bins[:-1]
    risk_bucket.to_csv(out("risk_distribution.csv"), index=False)

    print("\n12 CSVs written to %s" % args.out)


if __name__ == "__main__":
    main()
