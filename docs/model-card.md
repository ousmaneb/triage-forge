# Model card

## Risk model

- Type: `HistGradientBoostingClassifier` (scikit-learn), 200 iterations, 24 leaf nodes.
- Input: 17 behavioral features (failed logins, outbound bytes, distinct destinations, privileged account, host criticality, location mismatch, off-hours, encoded or hidden execution, download cradle, Office or script-host parent, external source or destination, LSASS access, recovery tampering, remote execution, command-line length).
- Output: probability that the alert is malicious, plus up to four reasons, ranked by permutation importance.
- Training data: 6,000 synthetic alerts (seed 7) across 8 ATT&CK techniques, 35% malicious, 4% label noise.
- Evaluation: 2,000 held-out alerts (seed 1234). ROC AUC 0.945, F1 0.928 at a 0.5 threshold.

## Technique classifier

- Type: character 3-5-gram TF-IDF with logistic regression.
- Input: rule name, description, process, parent process, command line.
- Classes: T1059.001, T1110, T1078, T1003.001, T1048, T1021.002, T1490, T1053.005.
- Evaluation: 0.959 accuracy on the held-out set. All 82 errors confuse T1110 (brute force) with T1078 (valid accounts) on alerts with a generic title: sign-in alerts carry no process or command line, so the text alone cannot separate them. The risk model does not use the technique label, so these errors do not change its score; Claude does see the predicted technique, alongside the failed-login count and location.

## What the numbers mean

The synthetic generator encodes realistic behavior, including benign activity that looks malicious, but it is still a model of the world written by hand. High scores here show the pipeline is wired correctly and give the CI gate a baseline to defend. Before relying on the models in a real SOC, retrain and re-evaluate them on that SOC's labeled alerts.
