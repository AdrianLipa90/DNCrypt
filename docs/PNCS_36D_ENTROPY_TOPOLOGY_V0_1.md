# PNCS 36D Entropy Topology v0.1

Status: `IMPLEMENTATION_CONFORMANCE_PROTOTYPE`

The topology gate evaluates each of the 36 live PhaseNav coordinates separately before any entropy budget is aggregated. Each coordinate receives an acceleration-residual binary stream and a conservative binary health estimate using MCV, first-order Markov and lag predictors.

Pairwise dependence is then measured by binary mutual information and direct pair-predictor advantage. A coordinate enters the selected mask only when its own health gate passes and its dependence on every previously selected coordinate remains below both thresholds.

Default selection thresholds:

- mutual information <= 0.08 bit;
- pair predictor advantage <= 0.12;
- per-channel estimated H_min >= 0.50 bit/sample.

The selected mask is dynamic and is recomputed per evidence window. It is not frozen into the DNCrypt protocol.

The selected streams are interleaved and independently health-tested before conditioning. SHAKE256 is used only after the selected-stream health gate passes.

## Live evidence

Two independent 72-frame windows were observed. One selected 13/36 coordinates. A subsequent validation window selected 17/36 coordinates; the selected set had maximum pairwise mutual information about 0.0383 bit and maximum pair-predictor advantage about 0.1143. The interleaved selected stream contained 1190 samples and passed the health gate with estimated H_min about 0.8997 bit/sample.

The changing masks establish that channel selection is window-dependent under the current live dynamics.
