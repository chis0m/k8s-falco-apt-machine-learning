# Falco APT Alert Detection - AI/ML in Cybersecurity CA (H9AIMLC)

This project builds a machine learning pipeline to detect APT (Advanced Persistent
Threat) attacks from Falco security alerts collected in a Kubernetes cluster, using
the [Falco-Alerts-Dataset-with-APT-attacks](https://github.com/simabagheri1/Falco-Alerts-Dataset-with-APT-attacks)
dataset (Bagheri et al., ICC 2023).

The project has two parts:

| Folder | What it is |
|---|---|
| [`notebooks/`](./notebooks) | The ML pipeline — data loading, feature engineering, model comparison across Logistic Regression, Random Forest, and XGBoost, each with 4 imbalance-handling strategies (vanilla, class-weighting, SMOTE, downsampling) |
| [`api/`](./api) | A containerized FastAPI service that serves the trained models, so predictions can be requested over HTTP instead of run through a notebook |

See each folder's own README for setup and usage instructions specific to that part.

## Quick start

**To explore the ML pipeline:**
```bash
cd notebooks
pip install -r requirements.txt
jupyter notebook
```
Then open the notebooks in order

**To run the trained models as an API:**
```bash
docker run -p 8000:8000 cl0ud/falco-apt-classifier
```
Then visit `http://localhost:8000/docs` — see [`api/README.md`](./api/README.md) for full details.

## How to get the data for this exercise
```bash
./notebooks

curl -L -o WARP_Falco_Alerts_Labeled_Dataset.zip https://raw.githubusercontent.com/simabagheri1/Falco-Alerts-Dataset-with-APT-attacks/master/WARP_Falco_Alerts_Labeled_Dataset.zip

unzip WARP_Falco_Alerts_Labeled_Dataset.zip
```

## Citation

> @inproceedings{bagheri2023warping,
   title={Warping the Defence Timeline: Non-disruptive Proactive Attack Mitigation for Kubernetes Clusters},
   author={Bagheri, Sima and Kermabon-Bobinnec, Hugo and Majumdar, Suryadipta and Jarraya, Yosr and Wang, Lingyu and Pourzandi, Makan},
   booktitle={ICC 2023-IEEE International Conference on Communications},
   pages={777--782},
   year={2023},
   organization={IEEE}
}

## Notes on the data found during exploration

- The dataset repo's README advertises 231K alerts (2,314 attack / 228,686 normal),
  but the actual usable **falco-alert-labeled-dataset** folder contains
  176,649 records (1,388 attack / 175,261 normal) across 10 pod files. One pod's
  raw alerts (`jzwkj`) were never processed into the labeled set.
- Attack alerts make up under 1% of the data, this class imbalance is the core
  challenge the model comparison in `notebooks/03_baseline_and_models.ipynb` is
  built around.