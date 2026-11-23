package selftest

import "math"

// mean returns the sample mean of x.
func mean(x []float64) float64 {
	if len(x) == 0 {
		return 0
	}
	var sum float64
	for _, v := range x {
		sum += v
	}
	return sum / float64(len(x))
}

// sampleVar returns the unbiased sample variance.
func sampleVar(x []float64) float64 {
	if len(x) < 2 {
		return 0
	}
	m := mean(x)
	var ss float64
	for _, v := range x {
		d := v - m
		ss += d * d
	}
	return ss / float64(len(x)-1)
}

// welchT is the two-sample Welch t-statistic for H0: mean(a)==mean(b).
// A large |t| means an attacker can distinguish the two secret classes;
// |t| < ~2 corresponds to no detectable difference at conventional levels.
//
// Zero-variance edge cases return a finite sentinel rather than +/-Inf so
// reports remain JSON-encodable: identical degenerate samples -> 0,
// perfectly separated degenerate samples -> +/-sentinelT.
const sentinelT = 1e6

func welchT(a, b []float64) float64 {
	ma, mb := mean(a), mean(b)
	va, vb := sampleVar(a), sampleVar(b)
	na, nb := float64(len(a)), float64(len(b))
	se := math.Sqrt(va/na + vb/nb)
	if se == 0 {
		if ma == mb {
			return 0
		}
		return sentinelT * sign(ma-mb)
	}
	return (ma - mb) / se
}

// dPrime is the standardized effect size |mean(a)-mean(b)| / pooled stddev.
// It is the attacker's signal-to-noise ratio: d' ~= 0 means no exploitable
// signal, d' >= ~1 is an easily exploitable channel.
func dPrime(a, b []float64) float64 {
	va, vb := sampleVar(a), sampleVar(b)
	pooled := math.Sqrt((va + vb) / 2)
	if pooled == 0 {
		if mean(a) == mean(b) {
			return 0
		}
		return sentinelT
	}
	return math.Abs(mean(a)-mean(b)) / pooled
}

// classifyAUC is the single-threshold classifier AUC (equivalent to the
// Mann-Whitney U statistic): the probability that a random class-1 sample
// scores higher than a random class-0 sample, with half credit for ties.
// It is threshold-free, so it measures channel strength without assuming
// Gaussian noise. AUC 0.5 = no channel; 1.0 = perfect separation.
func classifyAUC(class0, class1 []float64) float64 {
	var wins, total float64
	for _, x := range class0 {
		for _, y := range class1 {
			total++
			switch {
			case y > x:
				wins++
			case y == x:
				wins += 0.5
			}
		}
	}
	if total == 0 {
		return 0.5
	}
	return wins / total
}

// aucSignificant reports whether an AUC's departure from 0.5 is statistically
// significant at the two-sided 95% level. Under H0 (no channel) the
// Mann-Whitney U (= AUC * n0 * n1) is approximately normal with standard
// error sqrt(n0*n1*(n0+n1+1)/12); dividing by n0*n1 gives the standard error
// of the AUC itself: sqrt((n0+n1+1)/(12*n0*n1)). Tie correction is ignored,
// which slightly overstates significance and therefore errs on the
// attacker's side. Callers combine this with a fixed effect-size floor so
// that large samples do not turn negligible deviations into findings.
func aucSignificant(auc float64, n0, n1 int) bool {
	if n0 <= 1 || n1 <= 1 {
		return false
	}
	se := math.Sqrt(float64(n0+n1+1) / (12.0 * float64(n0) * float64(n1)))
	z := math.Abs(auc-0.5) / se
	return z >= 1.96
}

// maePct returns mean absolute error of estimates vs. reference, in percent.
func maePct(est, ref []float64) float64 {
	var sum float64
	for i := range est {
		if ref[i] == 0 {
			continue
		}
		sum += math.Abs(est[i]-ref[i]) / math.Abs(ref[i])
	}
	return 100 * sum / float64(len(est))
}

// rmse returns the root mean squared error.
func rmse(est, ref []float64) float64 {
	var ss float64
	for i := range est {
		d := est[i] - ref[i]
		ss += d * d
	}
	return math.Sqrt(ss / float64(len(est)))
}

func sign(x float64) float64 {
	if x < 0 {
		return -1
	}
	return 1
}
