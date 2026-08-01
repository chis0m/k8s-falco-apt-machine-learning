# Falco APT Alert Classifier

A containerized API that classifies Falco/Kubernetes runtime security alerts as
**attack** or **normal**, trained on the [Falco-Alerts-Dataset-with-APT-attacks](https://github.com/simabagheri1/Falco-Alerts-Dataset-with-APT-attacks) (Bagheri et al., ICC 2023). Includes the top 3 model/strategy combinations from model comparison (XGBoost, Random Forest, and Logistic Regression, each with class-weighting), so one can see how they respond to the same alert side by side.

## Quick start

**Locally:**
```bash
cd api/
# This tells python to use this as value for models directory
ENCODER_DIR="$(pwd)/encoder" \
MODELS_DIR="$(pwd)/models" \
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Docker:**
Pull and run the image:

```bash
docker run -p 8000:8000 cl0ud/falco-apt-classifier
```
The API is now running at `http://localhost:8000`.

## How To Test

**Option 1 - Interactive docs (easiest):**
Open http://localhost:8000/docs in your browser. Click on `/predict` or
`/predict/compare`, then "Try it out" to send a test alert without writing any code.

**Option 2 — using `curl`:**

```bash
curl http://localhost:8000/health
curl http://localhost:8000/models
```

**Test Cases**
```bash
curl -X POST http://localhost:8000/predict -H "Content-Type: application/json" -d '{
  "alert": {
    "priority": "Critical",
    "rule": "Launch Privileged Container",
    "mitre_tactic": "mitre_persistence",
    "user_name": "root",
    "image_repo": "busybox",
    "hour": 3,
    "cmdline_length": 80,
    "suspicious_cmd_flag": 1,
    "has_process_detail": 1,
    "has_file_event": 0
  }
}'
```

```bash
curl -X POST http://localhost:8000/predict -H "Content-Type: application/json" -d '{
  "alert": {
    "priority": "Critical",
    "rule": "Launch Privileged Container",
    "mitre_tactic": "mitre_persistence",
    "user_name": "root",
    "image_repo": "busybox",
    "hour": 3,
    "cmdline_length": 80,
    "suspicious_cmd_flag": 1,
    "has_process_detail": 1,
    "has_file_event": 0
  },
  "model": "logistic_regression"
}'
```

```bash
curl -X POST http://localhost:8000/predict/compare -H "Content-Type: application/json" -d '{
  "priority": "Critical",
  "rule": "Launch Privileged Container",
  "mitre_tactic": "mitre_persistence",
  "user_name": "root",
  "image_repo": "busybox",
  "hour": 3,
  "cmdline_length": 80,
  "suspicious_cmd_flag": 1,
  "has_process_detail": 1,
  "has_file_event": 0
}'
```

```bash
curl -X POST http://localhost:8000/predict/raw/compare -H "Content-Type: application/json" -d '  {
    "output": "20:30:47.024077548: Notice A shell was spawned in a container with an attached terminal (user=root user_loginuid=-1 k8s.ns=default k8s.pod=falco-4xs77 container=ef8ac1c64fa1 shell=bash parent=runc cmdline=bash terminal=34816 container_id=ef8ac1c64fa1 image=falcosecurity/falco) k8s.ns=default k8s.pod=falco-4xs77 container=ef8ac1c64fa1",
    "priority": "Notice",
    "rule": "Terminal shell in container",
    "source": "syscall",
    "tags": [
      "container",
      "mitre_execution",
      "shell"
    ],
    "time": "2021-11-19T20:30:47.024077548Z",
    "output_fields": {
      "container.id": "ef8ac1c64fa1",
      "container.image.repository": "falcosecurity/falco",
      "evt.time": 1637353847024077548,
      "k8s.ns.name": "default",
      "k8s.pod.name": "falco-4xs77",
      "proc.cmdline": "bash",
      "proc.name": "bash",
      "proc.pname": "runc",
      "proc.tty": 34816,
      "user.loginuid": -1,
      "user.name": "root"
    }
  }'
```

```bash
curl -X POST http://localhost:8000/predict/raw/compare -H "Content-Type: application/json" -d '  {
    "output": "43:01.904635092: Error an attempt to create a directory below a set of binary directories.(user=root user_loginuid=0 command=container:2a3553d75d4c k8s.ns=default k8s.pod=privileged-deployment-574878fc9d-cmdkr container=2a3553d75d4c image=busybox:latest)",
    "priority": "Error",
    "rule": "Launch Privileged Container",
    "source": "syscall",
    "tags": [
      "filesystem",
      "mitre_persistence"
    ],
    "time": "2021-11-19T22:43:01.904635092Z",
    "output_fields": {
      "container.id": "2a3553d75d4c",
      "container.image.repository": "busybox",
      "container.image.tag": "latest",
      "evt.time": 1637361781904635092,
      "k8s.ns.name": "default",
      "k8s.pod.name": "privileged-deployment-574878fc9d-cmdkr",
      "proc.cmdline": "container:2a3553d75d4c",
      "user.loginuid": 0,
      "user.name": "root"
    }
  }'
```


## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness check |
| GET | `/models` | Lists available models and the default |
| POST | `/predict` | Predict with one model (default or specified) |
| POST | `/predict/compare` | Predict with all loaded models at once |
| POST | `/predict/raw` | Predict with one model using raw falco alert |
| POST | `/predict/raw/compare` | Predict with all loaded models at once using raw falco alert |
| GET | `/docs` | Interactive Swagger UI |