// React Frontend Application Logic
// Implements dashboard states, live visual updates, and fully client-side password analysis.
// (Originally called a Flask API; ported to pure JS so this can be hosted as a static site, e.g. GitHub Pages.)

const { useState, useEffect } = React;

// ---------------------------------------------------------------------------
// Blacklist Config (ported from repeated_password.py)
// ---------------------------------------------------------------------------
const BLACKLIST = [
    // General repeated patterns
    "aaaaaa", "111111", "000000", "123123", "abcabc", "qwertyqwerty",
    "passwordpassword", "adminadmin", "letmeinletmein", "welcomewelcome",

    // Repeated character values
    "aaaaaa", "bbbbbb", "cccccc", "dddddd", "eeeeee", "ffffff",
    "gggggg", "hhhhhh", "iiiiii", "jjjjjj", "kkkkkk", "llllll",
    "mmmmmm", "nnnnnn", "oooooo", "pppppp", "qqqqqq", "rrrrrr",
    "ssssss", "tttttt", "uuuuuu", "vvvvvv", "wwwwww", "xxxxxx",
    "yyyyyy", "zzzzzz",

    // Additional predictable patterns
    "121212", "123123123", "abc123abc123", "passpass", "loginlogin",
    "testtest", "useruser", "rootroot", "guestguest",
    "admin123admin123", "qwerty123qwerty123",
].map((item) => item.toLowerCase());

// ---------------------------------------------------------------------------
// Core Password Strength Checker (ported from password_checker.py)
// ---------------------------------------------------------------------------
function analyzePassword(password) {
    // 1. CHARACTER POOL DETECTION
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const specialRegex = /[\!"#\$%&'\(\)\*\+,\-\.\/:;<=>\?@\[\\\]\^_`\{\|\}~]/;
    const hasSpecial = specialRegex.test(password);

    // 2. ENTROPY CALCULATION
    let poolSize = 0;
    if (hasLower) poolSize += 26;
    if (hasUpper) poolSize += 26;
    if (hasDigit) poolSize += 10;
    if (hasSpecial) poolSize += 32;

    const length = password.length;
    let entropy = (poolSize === 0 || length === 0) ? 0.0 : length * Math.log2(poolSize);
    entropy = Math.round(entropy * 100) / 100;

    // 3. BLACKLIST CHECKING (case-insensitive)
    const isBlacklisted = BLACKLIST.includes(password.toLowerCase());

    // 4. ORIGINAL PATTERN DETECTION
    const consecutiveMatch = password.match(/(.)\1\1/);
    const hasConsecutive = consecutiveMatch !== null;
    const consecutiveDetail = hasConsecutive ? consecutiveMatch[0] : null;

    const repeatedSubseqMatch = password.match(/(.{2,})\1/);
    const hasRepeatedSubseq = repeatedSubseqMatch !== null;
    const repeatedSubseqDetail = hasRepeatedSubseq ? repeatedSubseqMatch[1] : null;

    // 5. ENHANCED PATTERN DETECTION (sequential & keyboard runs)
    const detectedEnhancedPatternsSet = new Set();

    const seqDigitsForward = "01234567890";
    const seqDigitsBackward = "98765432109";
    for (let i = 0; i < password.length - 2; i++) {
        const sub = password.slice(i, i + 3).toLowerCase();
        if ((seqDigitsForward.includes(sub) || seqDigitsBackward.includes(sub)) && /^[0-9]+$/.test(sub)) {
            detectedEnhancedPatternsSet.add(`Sequential digits: '${sub}'`);
        }
    }

    const seqLettersForward = "abcdefghijklmnopqrstuvwxyz";
    const seqLettersBackward = "zyxwvutsrqponmlkjihgfedcba";
    for (let i = 0; i < password.length - 2; i++) {
        const sub = password.slice(i, i + 3).toLowerCase();
        if ((seqLettersForward.includes(sub) || seqLettersBackward.includes(sub)) && /^[a-z]+$/.test(sub)) {
            detectedEnhancedPatternsSet.add(`Sequential letters: '${sub}'`);
        }
    }

    const keyboardRows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"];
    for (const row of keyboardRows) {
        const revRow = row.split("").reverse().join("");
        for (let i = 0; i < password.length - 2; i++) {
            const sub = password.slice(i, i + 3).toLowerCase();
            if (row.includes(sub) || revRow.includes(sub)) {
                detectedEnhancedPatternsSet.add(`Keyboard run: '${sub}'`);
            }
        }
    }

    const detectedEnhancedPatterns = Array.from(detectedEnhancedPatternsSet);

    // 6. ORIGINAL RULE-BASED SCORING (100-point model)
    let ruleScore = 0;
    let lengthCheck;
    if (length >= 12) {
        ruleScore += 20;
        lengthCheck = true;
    } else if (length >= 8) {
        ruleScore += 10;
        lengthCheck = true;
    } else {
        lengthCheck = false;
    }

    if (hasUpper) ruleScore += 15;
    if (hasLower) ruleScore += 15;
    if (hasDigit) ruleScore += 10;
    if (hasSpecial) ruleScore += 15;
    if (!hasConsecutive) ruleScore += 10;
    if (!isBlacklisted) ruleScore += 15;

    ruleScore = Math.min(ruleScore, 100);

    // 7. ENHANCED HYBRID SECURITY SCORE & NORMALIZATION
    const normalizedEntropy = Math.min((entropy / 80.0) * 100.0, 100.0);
    let hybridScore = (0.4 * normalizedEntropy) + (0.6 * ruleScore);

    const penaltyReasons = [];

    // A. Blacklist Match -> cap 15
    if (isBlacklisted) {
        hybridScore = Math.min(hybridScore, 15.0);
        penaltyReasons.push("Password matches common/repeated blacklist (Score capped to 15)");
    }

    // B. Consecutive identical chars -> cap 45
    if (hasConsecutive) {
        hybridScore = Math.min(hybridScore, 45.0);
        penaltyReasons.push(`Contains consecutive identical chars '${consecutiveDetail}' (Score capped to 45)`);
    }

    // C. Repeated subsequence -> cap 50
    if (hasRepeatedSubseq) {
        hybridScore = Math.min(hybridScore, 50.0);
        penaltyReasons.push(`Contains repeated subsequence '${repeatedSubseqDetail}' (Score capped to 50)`);
    }

    // D. Predictable common words -> cap 50
    const predictableWords = ["password", "admin", "welcome", "letmein", "qwerty", "login", "guest"];
    const matchedWords = predictableWords.filter((w) => password.toLowerCase().includes(w));
    if (matchedWords.length > 0) {
        hybridScore = Math.min(hybridScore, 50.0);
        penaltyReasons.push(`Contains common base word '${matchedWords[0]}' (Score capped to 50)`);
    }

    // E. Sequential / keyboard runs -> deduct 10 per occurrence, cap 70
    if (detectedEnhancedPatterns.length > 0) {
        const deduction = detectedEnhancedPatterns.length * 10.0;
        hybridScore = Math.max(0.0, hybridScore - deduction);
        hybridScore = Math.min(hybridScore, 70.0);
        penaltyReasons.push(`Contains predictable keyboard/sequential runs (Deducted ${deduction} points, capped at 70)`);
    }

    // F. Entropy caps
    if (entropy < 40.0) {
        hybridScore = Math.min(hybridScore, 39.9);
        penaltyReasons.push("Low mathematical entropy (under 40 bits) caps strength to WEAK");
    } else if (entropy < 60.0) {
        hybridScore = Math.min(hybridScore, 59.9);
        penaltyReasons.push("Moderate mathematical entropy (under 60 bits) caps strength to MODERATE");
    } else if (entropy < 80.0) {
        hybridScore = Math.min(hybridScore, 79.9);
        penaltyReasons.push("Strong mathematical entropy (under 80 bits) caps strength to STRONG");
    }

    hybridScore = Math.round(hybridScore * 100) / 100;

    // 8. STRENGTH CLASSIFICATION
    let classification;
    if (hybridScore < 40.0) classification = "WEAK";
    else if (hybridScore < 60.0) classification = "MODERATE";
    else if (hybridScore < 80.0) classification = "STRONG";
    else classification = "VERY STRONG";

    // 9. RECOMMENDATION ENGINE
    const recommendations = [];
    if (length < 12) {
        if (length < 8) {
            recommendations.push("Increase password length to at least 12 characters (currently critically short).");
        } else {
            recommendations.push("Increase password length to at least 12 characters.");
        }
    }
    if (!hasUpper) recommendations.push("Add at least one uppercase letter.");
    if (!hasLower) recommendations.push("Add at least one lowercase letter.");
    if (!hasDigit) recommendations.push("Add at least one number.");
    if (!hasSpecial) recommendations.push("Add at least one special character.");
    if (hasConsecutive) recommendations.push(`Avoid repeated character sequences such as '${consecutiveDetail}'.`);
    if (hasRepeatedSubseq) recommendations.push(`Avoid repeating predictable sequences such as '${repeatedSubseqDetail}${repeatedSubseqDetail}'.`);
    if (isBlacklisted) recommendations.push("This password appears in a common/repeated password list. Choose a unique password.");
    if (matchedWords.length > 0) recommendations.push(`Avoid using common base words like '${matchedWords[0]}'.`);
    if (detectedEnhancedPatterns.length > 0) recommendations.push("Avoid predictable patterns (keyboard paths or sequential numbers/letters) that attackers commonly test.");

    if (length >= 12 && hasUpper && hasLower && hasDigit && hasSpecial &&
        !hasConsecutive && !hasRepeatedSubseq && !isBlacklisted &&
        matchedWords.length === 0 && detectedEnhancedPatterns.length === 0) {
        recommendations.push("Good password composition. Keep it unique and avoid reusing it across accounts.");
    }

    const checks = {
        uppercase: hasUpper,
        lowercase: hasLower,
        digit: hasDigit,
        special: hasSpecial,
        length: lengthCheck,
        repeated: !hasConsecutive,
        blacklist: !isBlacklisted,
    };

    const patterns = [];
    if (isBlacklisted) patterns.push("Blacklisted Password");
    if (hasConsecutive) patterns.push(`Consecutive identical: '${consecutiveDetail}'`);
    if (hasRepeatedSubseq) patterns.push(`Repeated subsequence: '${repeatedSubseqMatch[0]}'`);
    patterns.push(...detectedEnhancedPatterns);

    return {
        entropy,
        pool_size: poolSize,
        rule_score: ruleScore,
        hybrid_score: hybridScore,
        strength: classification,
        checks,
        patterns,
        recommendations,
        penalty_reasons: penaltyReasons,
        composition: {
            length,
            has_lower: hasLower,
            has_upper: hasUpper,
            has_digit: hasDigit,
            has_special: hasSpecial,
        },
    };
}

function App() {
    const [password, setPassword] = useState("");
    const [maskPassword, setMaskPassword] = useState(true);
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState(null);
    const [isAccordionOpen, setIsAccordionOpen] = useState(false);

    // Live feedback indicators computed instantly on the frontend as the user types
    const [liveIndicators, setLiveIndicators] = useState({
        length: false,
        uppercase: false,
        lowercase: false,
        digit: false,
        special: false,
        repeated: true, // No consecutive 3+ duplicates
        blacklist: true  // Default true until checked against blacklist on submit
    });

    // Run simple regular expression matches on client-side for immediate UI response
    useEffect(() => {
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasDigit = /[0-9]/.test(password);
        
        // Punctuation check matching string.punctuation ASCII chars
        const specialRegex = /[\!"#\$%&'\(\)\*\+,\-\.\/:;<=>\?@\[\\\]\^_`\{\|\}~]/;
        const hasSpecial = specialRegex.test(password);
        const meetsLength = password.length >= 8;

        // Check for 3 consecutive identical characters (e.g. aaa, 111)
        const hasConsecutive = /(.)\1\1/.test(password);

        setLiveIndicators({
            length: meetsLength,
            uppercase: hasUpper,
            lowercase: hasLower,
            digit: hasDigit,
            special: hasSpecial,
            repeated: !hasConsecutive,
            blacklist: true // Must click Analyze to verify against database
        });
    }, [password]);

    const handleClear = () => {
        setPassword("");
        setResults(null);
        setError(null);
    };

    const handleAnalyze = (e) => {
        e.preventDefault();
        if (!password) return;

        setLoading(true);
        setError(null);

        try {
            // Fully client-side analysis — no server round-trip, so the password
            // never leaves the browser. A short timeout keeps the "Analyzing..."
            // button state visible for a beat rather than flashing instantly.
            setTimeout(() => {
                try {
                    const data = analyzePassword(password);
                    setResults(data);
                } catch (err) {
                    setError("An error occurred during evaluation.");
                } finally {
                    setLoading(false);
                }
            }, 150);
        } catch (err) {
            setError(err.message);
            setLoading(false);
        }
    };

    // Calculate circular SVG progress variables
    const strokeRadius = 70;
    const strokeDashArray = 2 * Math.PI * strokeRadius; // ~439.82
    const currentScore = results ? results.hybrid_score : 0;
    const strokeDashOffset = strokeDashArray - (currentScore / 100) * strokeDashArray;

    // Helper to assign CSS classes based on strength
    const getStrengthClass = (strength) => {
        if (!strength) return "weak";
        const val = strength.toUpperCase();
        if (val === "WEAK") return "weak";
        if (val === "MODERATE") return "moderate";
        if (val === "STRONG") return "strong";
        return "very-strong";
    };

    return (
        <div>
            {/* Navigation Header */}
            <nav className="navbar">
                <a href="#" className="nav-brand">
                    <i className="fa-solid fa-shield-halved brand-icon"></i>
                    Intelligent Password Strength Analyzer
                </a>
                <ul className="nav-links">
                    <li><a href="#analyzer-section">Analyzer</a></li>
                    <li><a href="#how-it-works-section">How It Works</a></li>
                    <li><a href="#security-section">Security</a></li>
                    <li><a href="#about-section">About</a></li>
                </ul>
            </nav>

            <div className="container">
                {/* Hero Header */}
                <header className="hero">
                    <h1 className="hero-title">Intelligent Password Strength Analyzer</h1>
                    <p className="hero-subtitle">
                        Evaluate password security using hybrid entropy metrics and heuristic rule-based analysis to detect structural predictability.
                    </p>
                </header>

                <div className="dashboard-grid">
                    {/* Left Column: Form and Checklist */}
                    <div className="left-column">
                        <section id="analyzer-section" className="card fade-in-section">
                            <h2 className="card-title">
                                <i className="fa-solid fa-terminal"></i>
                                Analyze Your Password
                            </h2>
                            <form onSubmit={handleAnalyze}>
                                <div className="form-group">
                                    <div className="input-container">
                                        <i className="fa-solid fa-key input-icon-left"></i>
                                        <input
                                            type={maskPassword ? "password" : "text"}
                                            value={password}
                                            onChange={(e) => setPassword(e.target.value)}
                                            placeholder="Enter password to evaluate..."
                                            className="input-field input-field-with-icon"
                                            autoComplete="off"
                                        />
                                        <button
                                            type="button"
                                            onClick={() => setMaskPassword(!maskPassword)}
                                            className="toggle-visibility-btn"
                                            title={maskPassword ? "Show Password" : "Hide Password"}
                                        >
                                            <i className={maskPassword ? "fa-solid fa-eye-slash" : "fa-solid fa-eye"}></i>
                                        </button>
                                    </div>
                                </div>

                                <div className="btn-group">
                                    <button 
                                        type="submit" 
                                        className="btn btn-primary"
                                        disabled={loading || !password}
                                    >
                                        {loading ? (
                                            <>
                                                <i className="fa-solid fa-spinner fa-spin"></i>
                                                Analyzing...
                                            </>
                                        ) : (
                                            <>
                                                <i className="fa-solid fa-magnifying-glass-chart"></i>
                                                Analyze Password
                                            </>
                                        )}
                                    </button>
                                    <button 
                                        type="button" 
                                        onClick={handleClear} 
                                        className="btn btn-secondary"
                                        disabled={loading || !password}
                                    >
                                        <i className="fa-solid fa-trash-can"></i>
                                        Clear
                                    </button>
                                </div>
                            </form>

                            {error && (
                                <div className="overall-assessment" style={{ borderColor: 'var(--danger)', color: 'var(--danger)', marginTop: '1.5rem', background: 'var(--danger-bg)' }}>
                                    <i className="fa-solid fa-circle-exclamation" style={{ marginRight: '0.5rem' }}></i>
                                    {error}
                                </div>
                            )}
                        </section>

                        {/* Heuristic Checklist Dashboard */}
                        <section className="card fade-in-section">
                            <h2 className="card-title">
                                <i className="fa-solid fa-list-check"></i>
                                Rule-Based Checklist
                            </h2>
                            <div className="checklist-container">
                                <div className={`checklist-item ${liveIndicators.length ? 'pass' : 'fail'}`}>
                                    <i className={liveIndicators.length ? "fa-solid fa-circle-check" : "fa-solid fa-circle-xmark"}></i>
                                    <span className="checklist-text">Minimum Recommended Length (8+ characters)</span>
                                </div>
                                <div className={`checklist-item ${liveIndicators.uppercase ? 'pass' : 'fail'}`}>
                                    <i className={liveIndicators.uppercase ? "fa-solid fa-circle-check" : "fa-solid fa-circle-xmark"}></i>
                                    <span className="checklist-text">Contains Uppercase Letter</span>
                                </div>
                                <div className={`checklist-item ${liveIndicators.lowercase ? 'pass' : 'fail'}`}>
                                    <i className={liveIndicators.lowercase ? "fa-solid fa-circle-check" : "fa-solid fa-circle-xmark"}></i>
                                    <span className="checklist-text">Contains Lowercase Letter</span>
                                </div>
                                <div className={`checklist-item ${liveIndicators.digit ? 'pass' : 'fail'}`}>
                                    <i className={liveIndicators.digit ? "fa-solid fa-circle-check" : "fa-solid fa-circle-xmark"}></i>
                                    <span className="checklist-text">Contains Number</span>
                                </div>
                                <div className={`checklist-item ${liveIndicators.special ? 'pass' : 'fail'}`}>
                                    <i className={liveIndicators.special ? "fa-solid fa-circle-check" : "fa-solid fa-circle-xmark"}></i>
                                    <span className="checklist-text">Contains Special Character</span>
                                </div>
                                <div className={`checklist-item ${!password ? '' : (liveIndicators.repeated ? 'pass' : 'fail')}`}>
                                    <i className={!password ? "fa-solid fa-circle-question" : (liveIndicators.repeated ? "fa-solid fa-circle-check" : "fa-solid fa-circle-xmark")}></i>
                                    <span className="checklist-text">No Repeated Consecutive Chars (e.g. aaa, 111)</span>
                                </div>
                                <div className={`checklist-item ${results ? (results.checks.blacklist ? 'pass' : 'fail') : 'fail'}`}>
                                    <i className={results ? (results.checks.blacklist ? "fa-solid fa-circle-check" : "fa-solid fa-circle-xmark") : "fa-solid fa-circle-question"}></i>
                                    <span className="checklist-text">Not a Common/Blacklisted Password {!results && "(requires analysis)"}</span>
                                </div>
                            </div>
                        </section>
                    </div>

                    {/* Right Column: Security HUD Gauge (Displays only when results exist) */}
                    <div className="right-column">
                        {results ? (
                            <div className="card strength-summary-card fade-in-section">
                                <h3 className="gauge-label">Security Rating</h3>
                                <div className="progress-ring-container">
                                    <svg className="progress-ring" width="180" height="180">
                                        <circle
                                            className="progress-ring-circle-bg"
                                            cx="90"
                                            cy="90"
                                            r={strokeRadius}
                                        />
                                        <circle
                                            className={`progress-ring-circle ${getStrengthClass(results.strength)}`}
                                            cx="90"
                                            cy="90"
                                            r={strokeRadius}
                                            strokeDasharray={strokeDashArray}
                                            strokeDashoffset={strokeDashOffset}
                                        />
                                    </svg>
                                    <div className="gauge-percentage">
                                        <span className="gauge-num">{results.hybrid_score}</span>
                                        <span className="gauge-label">Hybrid Score</span>
                                    </div>
                                </div>
                                <div className={`strength-val ${getStrengthClass(results.strength)}`}>
                                    {results.strength}
                                </div>

                                <div className="metrics-grid">
                                    <div className="metric-mini-card">
                                        <div className="metric-mini-title">Entropy</div>
                                        <div className="metric-mini-val">
                                            {results.entropy} <span>bits</span>
                                        </div>
                                    </div>
                                    <div className="metric-mini-card">
                                        <div className="metric-mini-title">Rule Score</div>
                                        <div className="metric-mini-val">
                                            {results.rule_score}<span>/100</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ) : (
                            <div className="card strength-summary-card fade-in-section" style={{ minHeight: '340px' }}>
                                <i className="fa-solid fa-lock brand-icon" style={{ fontSize: '4.5rem', marginBottom: '1.5rem', opacity: 0.15 }}></i>
                                <h3 style={{ color: 'var(--text-secondary)', fontWeight: '500' }}>Awaiting Password Analysis</h3>
                                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '0.5rem', maxWidth: '280px', lineHeight: '1.5' }}>
                                    Input your password on the left and click "Analyze" to execute the hybrid vulnerability evaluation.
                                </p>
                            </div>
                        )}
                    </div>
                </div>

                {/* Dashboard Panels (Only show when results are loaded) */}
                {results && (
                    <div className="fade-in-section">
                        {/* Hybrid Security Analysis Dashboard */}
                        <section className="card">
                            <h2 className="card-title">
                                <i className="fa-solid fa-shield-halved"></i>
                                Hybrid Security Analysis Breakdown
                            </h2>
                            <div className="hybrid-sections">
                                <div className="hybrid-panel-card">
                                    <div className="hybrid-panel-header">
                                        <i className="fa-solid fa-calculator"></i>
                                        Entropy Analysis
                                    </div>
                                    <div className="hybrid-stat">{results.entropy} bits</div>
                                    <p className="hybrid-desc">
                                        Calculates the mathematical difficulty of brute-forcing the password, based on length and a character class pool of size {results.pool_size}.
                                    </p>
                                </div>

                                <div className="hybrid-panel-card">
                                    <div className="hybrid-panel-header">
                                        <i className="fa-solid fa-list-ol"></i>
                                        Rule-Based Score
                                    </div>
                                    <div className="hybrid-stat">{results.rule_score}/100</div>
                                    <p className="hybrid-desc">
                                        Applies standard policy checks for uppercase, lowercase, digits, symbols, and length limits, assigning discrete weights.
                                    </p>
                                </div>

                                <div className="hybrid-panel-card">
                                    <div className="hybrid-panel-header">
                                        <i className="fa-solid fa-magnifying-glass"></i>
                                        Patterns & Blacklist
                                    </div>
                                    <div className="hybrid-stat">
                                        {results.patterns.length > 0 ? (
                                            <span style={{ color: 'var(--danger)' }}>Pattern Found</span>
                                        ) : (
                                            <span style={{ color: 'var(--success)' }}>None Detected</span>
                                        )}
                                    </div>
                                    <p className="hybrid-desc">
                                        Scans for consecutive letters, keyboard rows, repeated substrings, or exact matches inside common credentials database.
                                    </p>
                                    {results.patterns.length > 0 && (
                                        <ul className="hybrid-warnings">
                                            {results.patterns.map((pat, idx) => (
                                                <li className="hybrid-warning-item" key={idx}>
                                                    <i className="fa-solid fa-circle-exclamation"></i>
                                                    {pat}
                                                </li>
                                            ))}
                                        </ul>
                                    )}
                                </div>
                            </div>

                            {/* Overall Hybrid Assessment */}
                            <div className="overall-assessment">
                                <h4 style={{ fontWeight: '700', marginBottom: '0.25rem', color: 'var(--accent-cyan)' }}>
                                    Overall Hybrid Assessment
                                </h4>
                                {results.penalty_reasons.length > 0 ? (
                                    <div>
                                        <p style={{ marginBottom: '0.5rem' }}>
                                            Although the password might satisfy complexity rules or have high mathematical entropy, its strength was downgraded due to structural predictability:
                                        </p>
                                        <ul style={{ paddingLeft: '1.25rem' }}>
                                            {results.penalty_reasons.map((reason, idx) => (
                                                <li key={idx} style={{ color: 'var(--warning)', listStyleType: 'square', marginBottom: '0.25rem' }}>
                                                    {reason}
                                                </li>
                                            ))}
                                        </ul>
                                    </div>
                                ) : (
                                    <p>
                                        The password shows strong mathematical resistance (entropy) and adheres properly to structural guidelines, without any detectable predictable sequences or keyboard runs.
                                    </p>
                                )}
                            </div>
                        </section>

                        {/* Entropy Slider Meter */}
                        <section className="card">
                            <h2 className="card-title">
                                <i className="fa-solid fa-gauge-high"></i>
                                Mathematical Entropy Meter
                            </h2>
                            <div className="entropy-meter-container">
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <span style={{ color: 'var(--text-secondary)', fontWeight: '500' }}>
                                        Strength Level: <strong style={{ color: 'var(--accent-cyan)' }}>{results.entropy} bits</strong>
                                    </span>
                                </div>
                                <div className="entropy-slider-track">
                                    <div 
                                        className="entropy-slider-fill"
                                        style={{ width: `${Math.min((results.entropy / 100) * 100, 100)}%` }}
                                    ></div>
                                    <div 
                                        className="entropy-slider-marker"
                                        style={{ left: `${Math.min((results.entropy / 100) * 100, 100)}%` }}
                                    ></div>
                                </div>
                                <div className="entropy-labels">
                                    <span>0 (Weak)</span>
                                    <span>40 (Moderate)</span>
                                    <span>60 (Strong)</span>
                                    <span>80 (Very Strong)</span>
                                    <span>100+</span>
                                </div>
                                
                                <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginTop: '1.5rem', lineHeight: '1.5' }}>
                                    <strong>Entropy</strong> estimates resistance to brute-force guessing based on password length and character pool. A larger character pool exponentially increases the number of guesses required.
                                </p>

                                {/* Accordion for Formula */}
                                <div className={`accordion ${isAccordionOpen ? 'open' : ''}`}>
                                    <div 
                                        className="accordion-header"
                                        onClick={() => setIsAccordionOpen(!isAccordionOpen)}
                                    >
                                        <span>How Entropy is Calculated</span>
                                        <i className={isAccordionOpen ? "fa-solid fa-chevron-up" : "fa-solid fa-chevron-down"}></i>
                                    </div>
                                    <div className="accordion-content">
                                        <p>Entropy is calculated using the following thermodynamic information-theory formula:</p>
                                        <div className="math-formula">
                                            Entropy = L {"\u00d7"} log<sub>2</sub>(N)
                                        </div>
                                        <p style={{ marginBottom: '1rem' }}>
                                            Where <strong>L</strong> is the password length, and <strong>N</strong> is the pool size. 
                                            The pool size is the sum of characters in the matching character classes that actually occur in the password:
                                        </p>
                                        <table className="math-table">
                                            <thead>
                                                <tr>
                                                    <th>Character Class</th>
                                                    <th>Size (N)</th>
                                                    <th>Occurs?</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <tr>
                                                    <td>Lowercase letters (a-z)</td>
                                                    <td>26</td>
                                                    <td>{results.composition.has_lower ? "Yes (+26)" : "No (+0)"}</td>
                                                </tr>
                                                <tr>
                                                    <td>Uppercase letters (A-Z)</td>
                                                    <td>26</td>
                                                    <td>{results.composition.has_upper ? "Yes (+26)" : "No (+0)"}</td>
                                                </tr>
                                                <tr>
                                                    <td>Numeric digits (0-9)</td>
                                                    <td>10</td>
                                                    <td>{results.composition.has_digit ? "Yes (+10)" : "No (+0)"}</td>
                                                </tr>
                                                <tr>
                                                    <td>Special Characters (punctuation)</td>
                                                    <td>32</td>
                                                    <td>{results.composition.has_special ? "Yes (+32)" : "No (+0)"}</td>
                                                </tr>
                                            </tbody>
                                        </table>
                                        <p style={{ marginTop: '0.75rem', fontWeight: '600', color: 'var(--accent-cyan)' }}>
                                            Calculation for this password: {results.composition.length} {"\u00d7"} log<sub>2</sub>({results.pool_size}) = {results.entropy} bits.
                                        </p>
                                    </div>
                                </div>
                            </div>
                        </section>

                        {/* Actionable Recommendations Panel */}
                        <section className="card">
                            <h2 className="card-title">
                                <i className="fa-solid fa-circle-info"></i>
                                Security Recommendations
                            </h2>
                            <div className="recs-container">
                                {/* Actual issues render as warnings; the positive "good composition" message is excluded here so it isn't shown twice */}
                                {results.recommendations
                                    .filter((rec) => !rec.includes("Good password composition"))
                                    .map((rec, idx) => (
                                        <div className="rec-item warning" key={idx}>
                                            <i className="fa-solid fa-circle-exclamation"></i>
                                            <span>{rec}</span>
                                        </div>
                                    ))}

                                {/* Show a single success message when there are no issues to flag */}
                                {results.recommendations.length === 0 || 
                                 (results.recommendations.length === 1 && results.recommendations[0].includes("Good password composition")) ? (
                                    <div className="rec-item success">
                                        <i className="fa-solid fa-circle-check"></i>
                                        <span>Good password composition. Keep it unique and avoid reusing it across accounts.</span>
                                    </div>
                                ) : null}
                            </div>
                        </section>
                    </div>
                )}

                {/* How It Works Diagram */}
                <section id="how-it-works-section" className="card fade-in-section">
                    <h2 className="card-title">
                        <i className="fa-solid fa-circle-nodes"></i>
                        How It Works
                    </h2>
                    <p style={{ fontSize: '0.95rem', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                        The analyzer evaluates password strength in real-time through a 5-step pipelined security architecture:
                    </p>
                    <div className="process-steps">
                        <div className="process-step">
                            <span className="step-num">1</span>
                            <h3 className="step-title">Enter Password</h3>
                            <p className="step-desc">Input password securely in the client interface.</p>
                        </div>
                        <div className="process-step">
                            <span className="step-num">2</span>
                            <h3 className="step-title">Detect Pools</h3>
                            <p className="step-desc">Checks occurring classes: Lower, Upper, Digits, Symbols.</p>
                        </div>
                        <div className="process-step">
                            <span className="step-num">3</span>
                            <h3 className="step-title">Calc Entropy</h3>
                            <p className="step-desc">Applies log<sub>2</sub>(N) formula to assess brute-force resistance.</p>
                        </div>
                        <div className="process-step">
                            <span className="step-num">4</span>
                            <h3 className="step-title">Rule Score</h3>
                            <p className="step-desc">Evaluates standard complexity rules on 100pt scale.</p>
                        </div>
                        <div className="process-step">
                            <span className="step-num">5</span>
                            <h3 className="step-title">Hybrid Result</h3>
                            <p className="step-desc">Applies pattern caps and merges metrics for final assessment.</p>
                        </div>
                    </div>
                </section>

                {/* Security/Privacy Guarantee */}
                <section id="security-section" className="card fade-in-section">
                    <h2 className="card-title">
                        <i className="fa-solid fa-user-shield"></i>
                        Security & Privacy Policy
                    </h2>
                    <p style={{ fontSize: '0.95rem', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                        This tool has been built following the strict privacy guidelines outlined in the internship mandate:
                    </p>
                    <div className="security-bullets">
                        <div className="sec-bullet">
                            <i className="fa-solid fa-microchip"></i>
                            <div>
                                <h4 className="sec-bullet-title">Local Browser Processing</h4>
                                <p className="sec-bullet-desc">All analytical functions run entirely inside your browser. Passwords are never transmitted to a server or stored anywhere.</p>
                            </div>
                        </div>
                        <div className="sec-bullet">
                            <i className="fa-solid fa-server"></i>
                            <div>
                                <h4 className="sec-bullet-title">Zero Data Logging</h4>
                                <p className="sec-bullet-desc">We do not store, write, console print, or log your password. The API strictly processes and discards the string immediately.</p>
                            </div>
                        </div>
                        <div className="sec-bullet">
                            <i className="fa-solid fa-ban"></i>
                            <div>
                                <h4 className="sec-bullet-title">No External API Integration</h4>
                                <p className="sec-bullet-desc">No external breach databases or third-party query engines are used. This prevents leakage or sniffing of client input.</p>
                            </div>
                        </div>
                        <div className="sec-bullet">
                            <i className="fa-solid fa-code"></i>
                            <div>
                                <h4 className="sec-bullet-title">Transparent Logic</h4>
                                <p className="sec-bullet-desc">Code uses standard mathematical equations and regex engines rather than unexplainable neural networks, ideal for academic audits.</p>
                            </div>
                        </div>
                    </div>
                </section>

                {/* About Project Section */}
                <section id="about-section" className="card fade-in-section">
                    <h2 className="card-title">
                        <i className="fa-solid fa-address-card"></i>
                        About the Project
                    </h2>
                    <div className="about-grid">
                        <div className="about-details">
                            <div className="about-row">
                                <span className="about-label">Project Title:</span>
                                <span className="about-val">Intelligent Password Strength Analyzer Using Hybrid Entropy and Rule-Based Evaluation</span>
                            </div>
                            <div className="about-row">
                                <span className="about-label">Internship Organization:</span>
                                <span className="about-val">Approtech R&D Solutions Private Limited</span>
                            </div>
                            <div className="about-row">
                                <span className="about-label">Domain:</span>
                                <span className="about-val">Cyber Security</span>
                            </div>
                            <div className="about-row">
                                <span className="about-label">Student Name:</span>
                                <span className="about-val">K Kenneth Prathap</span>
                            </div>
                            <div className="about-row">
                                <span className="about-label">Department:</span>
                                <span className="about-val">Department of Computer Science and Engineering (Cyber Security)</span>
                            </div>
                        </div>
                        <div>
                            <p className="about-text">
                                This web application serves as the capstone demonstration for K Kenneth Prathap's cybersecurity internship. 
                                The design addresses a major security flaw in basic password strength indicators: the blind trust in composition criteria (uppercase, digit, symbol) which often permits easily guessable passwords like <code>Password@123</code>.
                            </p>
                            <p className="about-text" style={{ marginTop: '1rem' }}>
                                By combining mathematical entropy (entropy of characters pool) with localized heuristic checklists and pattern caps, the model delivers a reliable security assessment suitable for modern cybersecurity requirements.
                            </p>
                        </div>
                    </div>
                </section>
            </div>

            <footer className="footer">
                <p>All Rights Reserved {"\u00a9"} {new Date().getFullYear()}</p>
                <p style={{ fontSize: '0.75rem', marginTop: '0.25rem', color: 'var(--text-muted)' }}>Project developed by Kenneth Prathap</p>
            </footer>
        </div>
    );
}

// Render the application into root element
const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);
