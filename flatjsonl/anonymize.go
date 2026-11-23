package flatjsonl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// defaultAnonymizeSalt is mixed into codename hashing when no salt is configured.
//
// A configured, private salt is strongly recommended: it makes the mapping
// impossible to reverse by hashing a dictionary of known identifiers, while
// keeping it stable for the same salt.
const defaultAnonymizeSalt = "flatjsonl-anonymize-v1"

// codenameBytes is the number of hash bytes exposed in a codename.
//
// 96 bits keep the probability of accidental collisions negligible even for
// billions of distinct identifiers, so downstream joins preserve the original
// number of devices.
const codenameBytes = 12

// anonymizer replaces real identifiers with stable irreversible codenames.
//
// Codenames depend only on the configured salt and the original value, not on
// the column, the input file or the run, so the same real device gets the same
// codename in every stream and every output.
type anonymizer struct {
	salt []byte
	ck   func(string) string

	// literalKeys match canonical (case-folded) flat keys selected by
	// anonymizeKeys.
	literalKeys []*regexp.Regexp

	// regexKeys match original flat keys selected by anonymizeKeysRegex.
	regexKeys []*regexp.Regexp

	// literalElements match canonical leaves of selected identifier arrays,
	// e.g. ".deviceIds.[0]" for a selection of ".deviceIds".
	literalElements []*regexp.Regexp

	// names describe objects selected as a whole whose child keys are
	// identifiers, e.g. ".devices" flattened as ".devices.<device id>.temp".
	names []namePattern

	// patterns are the configured selections, canonicalized and stripped of
	// regular expression syntax, used to cheaply skip irrelevant values.
	patterns []string

	// jsonKeys, jsonPatterns describe keys kept as JSON literals, either
	// explicitly or by a high cardinality parent, so their values are sanitized
	// recursively instead of being treated as plain scalars.
	jsonKeys     map[string]bool
	jsonPatterns []*regexp.Regexp
}

// namePattern is a selection that marks positions in a flat path as identifier
// name segments, e.g. ".devices" (its children) or ".devices.*.id" (the
// wildcard).
type namePattern struct {
	segments []string     // Canonical segments, "*" matches one arbitrary segment.
	ids      map[int]bool // Positions that hold identifiers.
}

func newAnonymizer(cfg Config, ck func(string) string) (*anonymizer, error) {
	if len(cfg.AnonymizeKeys) == 0 && len(cfg.AnonymizeKeysRegex) == 0 {
		return nil, nil
	}

	a := &anonymizer{ck: ck, jsonKeys: map[string]bool{}}

	if len(cfg.KeepJSON) > 0 {
		for _, k := range cfg.KeepJSON {
			a.jsonKeys[k] = true
		}
	}

	for _, p := range cfg.KeepJSONRegex {
		r, err := regex(p)
		if err != nil {
			return nil, err
		}

		a.jsonPatterns = append(a.jsonPatterns, r)
	}

	if cfg.AnonymizeSalt != "" {
		a.salt = []byte(cfg.AnonymizeSalt)
	} else {
		a.salt = []byte(defaultAnonymizeSalt)
	}

	for _, p := range cfg.AnonymizeKeys {
		if p == "" {
			continue
		}

		keyReg := ck(p)

		r, err := regex(keyReg)
		if err != nil {
			return nil, err
		}

		a.literalKeys = append(a.literalKeys, r)
		a.patterns = append(a.patterns, keyReg)

		// Selecting an array also selects its elements, e.g. ".deviceIds.[0]"
		// for ".deviceIds".
		if er, err := regex(keyReg + ".[*]"); err == nil {
			a.literalElements = append(a.literalElements, er)
		}

		if np, ok := parseNamePattern(p, ck); ok {
			a.names = append(a.names, np)
		}
	}

	for _, p := range cfg.AnonymizeKeysRegex {
		if p == "" {
			continue
		}

		r, err := regex(p)
		if err != nil {
			return nil, err
		}

		a.regexKeys = append(a.regexKeys, r)
		a.patterns = append(a.patterns, ck(p))
	}

	return a, nil
}

// parseNamePattern extracts identifier-name positions from a literal selection.
//
// A trailing wildcard marks the selected position itself as an identifier
// (".devices.*" means ".devices.<device id>"), whereas a selection without
// wildcards marks the children of the selected path (".devices" means the keys
// of the ".devices" object). A wildcard elsewhere selects values rather than a
// name segment, so no position is marked.
func parseNamePattern(pattern string, ck func(string) string) (namePattern, bool) {
	if !strings.HasPrefix(pattern, ".") {
		return namePattern{}, false
	}

	segments := splitFlatKey(pattern)
	if len(segments) == 0 {
		return namePattern{}, false
	}

	np := namePattern{segments: make([]string, len(segments)), ids: map[int]bool{}}

	wildcards := 0

	for i, s := range segments {
		if s == "" {
			return namePattern{}, false
		}

		if s == "*" {
			np.segments[i] = s
			wildcards++

			continue
		}

		// Regular expression syntax means this is not a literal selection.
		if strings.ContainsAny(s, `()|+?^$\{`) {
			return namePattern{}, false
		}

		np.segments[i] = ck(s)
	}

	switch {
	case wildcards == 0:
		np.ids[len(segments)] = true
	case wildcards == 1 && segments[len(segments)-1] == "*":
		np.ids[len(segments)-1] = true
	}

	return np, true
}

// splitFlatKey splits a flat key into path segments, e.g. ".a.b.[0]" becomes
// "a", "b", "[0]".
func splitFlatKey(key string) []string {
	key = strings.TrimPrefix(key, ".")

	if key == "" {
		return nil
	}

	return strings.Split(key, ".")
}

// matches reports whether a flat key holds a real identifier to be anonymized.
func (a *anonymizer) matches(flatKey string) bool {
	if a == nil {
		return false
	}

	canonical := a.ck(flatKey)

	for _, r := range a.literalKeys {
		if r.MatchString(canonical) {
			return true
		}
	}

	for _, r := range a.literalElements {
		if r.MatchString(canonical) {
			return true
		}
	}

	for _, r := range a.regexKeys {
		if r.MatchString(flatKey) {
			return true
		}
	}

	return false
}

// childIsIdentifier reports whether a child key of the object at base is an
// identifier, which matters when the object is kept as a JSON literal.
func (a *anonymizer) childIsIdentifier(base string, key string) bool {
	if a == nil {
		return false
	}

	baseSegments := splitFlatKey(base)
	childSegments := append(baseSegments[:len(baseSegments):len(baseSegments)], key)

	// Literal selections mark the children position directly.
	if a.nameIsIdentifier(childSegments, len(baseSegments)) {
		return true
	}

	childPath := "." + strings.Join(childSegments, ".")
	basePath := "." + strings.Join(baseSegments, ".")

	for _, r := range a.regexKeys {
		// The selection addresses the child itself (".devices.<id>") or the
		// object as a whole (".devices"), in which case its keys are
		// identifiers.
		if r.MatchString(childPath) || r.MatchString(basePath) {
			return true
		}
	}

	return false
}

// keyedObject reports whether a flat key is an object whose child keys are
// identifiers, e.g. ".byDevice" for a selection of ".byDevice".
func (a *anonymizer) keyedObject(flatKey string) bool {
	if a == nil {
		return false
	}

	segments := splitFlatKey(flatKey)

	return a.nameIsIdentifier(segments, len(segments))
}

// nameIsIdentifier reports whether the i-th segment of a flat key is an
// identifier used as an object key; i may be len(segments) for a child key that
// is not part of the path yet.
func (a *anonymizer) nameIsIdentifier(segments []string, i int) bool {
	for _, np := range a.names {
		if !np.ids[i] {
			continue
		}

		match := true

		for j := 0; j < i; j++ {
			if j >= len(np.segments) {
				match = false

				break
			}

			if np.segments[j] == "*" {
				continue
			}

			if j >= len(segments) || a.ck(segments[j]) != np.segments[j] {
				match = false

				break
			}
		}

		if match {
			return true
		}
	}

	if len(a.regexKeys) == 0 || i >= len(segments) {
		// Regexes are only consulted for segments that are part of the key;
		// child keys of a kept JSON object are checked by childIsIdentifier.
		return false
	}

	// The selection must address the path through the segment but not the whole
	// key, e.g. "^\.byDevice\.[^.]+$" for ".byDevice.<id>.temp".
	prefix := "." + strings.Join(segments[:i+1], ".")
	full := "." + strings.Join(segments, ".")

	for _, r := range a.regexKeys {
		if r.MatchString(prefix) && !r.MatchString(full) {
			return true
		}
	}

	return false
}

// keyName anonymizes identifier segments exposed as part of a column name, e.g.
// an object keyed by device ids flattened to ".devices.<device id>.temperature".
//
// Without this, the codename would only appear in values and the original
// identifier would still leak in target column names.
func (a *anonymizer) keyName(flatKey string) string {
	if a == nil {
		return flatKey
	}

	segments := splitFlatKey(flatKey)
	if len(segments) < 2 {
		// A top-level key is never a name segment of another column.
		return flatKey
	}

	found := false

	for i, s := range segments {
		// Array indexes are positional, they do not hold identifiers.
		if i == 0 || s == "" || s[0] == '[' || !a.nameIsIdentifier(segments, i) {
			continue
		}

		segments[i] = a.codename(s)
		found = true
	}

	if !found {
		return flatKey
	}

	return "." + strings.Join(segments, ".")
}

// jsonLiteral reports whether a key is configured to be kept as a JSON literal.
func (a *anonymizer) jsonLiteral(flatKey string) bool {
	if a == nil {
		return false
	}

	if a.jsonKeys[flatKey] {
		return true
	}

	for _, r := range a.jsonPatterns {
		if r.MatchString(flatKey) {
			return true
		}
	}

	return false
}

// mayContainNested reports whether a selection addresses something below the
// given flat key, so the key may hold a JSON literal with identifiers inside.
func (a *anonymizer) mayContainNested(flatKey string) bool {
	if a == nil {
		return false
	}

	key := a.ck(flatKey)

	for _, p := range a.patterns {
		p = stripRegexSyntax(p)

		if len(p) > len(key) && strings.HasPrefix(p, key) {
			return true
		}
	}

	return false
}

func stripRegexSyntax(p string) string {
	return strings.NewReplacer("^", "", "$", "", `\`, "").Replace(p)
}

// anonymizeTransposedKey replaces an identifier used as an object key of a
// transposed table with its codename, so that the detail table references the
// same synthetic key as regular anonymized columns.
func (p *Processor) anonymizeTransposedKey(k *flKey) {
	a := p.anonymizer
	if a == nil {
		return
	}

	an := a.keyName(k.original)
	if an != k.original {
		// Re-derive the transposed key and trimmed path from the anonymized
		// name. The prefix is trimmed as literal text, so it is anonymized in
		// the same way before matching.
		tmp := flKey{original: an}
		scanTransposedKey(k.transposeDst, a.keyName(k.transposePrefix), &tmp)

		k.transposeKey = tmp.transposeKey
		k.transposeTrimmed = tmp.transposeTrimmed

		return
	}

	// A transposed object keyed by identifiers exposes them through its
	// "._index" value, which is not part of the column name.
	if k.transposeKey.t == TypeString {
		if base := k.transposePrefix; a.keyedObject(base) ||
			a.childIsIdentifier(base, k.transposeKey.s) {
			k.transposeKey.s = a.codename(k.transposeKey.s)
		}
	}
}

// anonymizeJSON sanitizes a JSON object or array literal kept as a single value
// (by keepJSON or by a high cardinality parent) so identifiers inside it are
// replaced too.
//
// ok is false when raw is not a JSON object or array, so callers can fall back
// to treating it as a scalar value.
func (a *anonymizer) anonymizeJSON(base string, raw string) (string, bool) {
	if a == nil {
		return raw, false
	}

	// Cheap guard: only structured values need decoding.
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		return raw, false
	}

	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()

	var v any
	if err := dec.Decode(&v); err != nil {
		return raw, false
	}

	switch v.(type) { //nolint:exhaustive
	case map[string]any, []any:
	default:
		return raw, false
	}

	nv, changed := a.anonymizeJSONValue(base, v)
	if !changed {
		return raw, true
	}

	b, err := json.Marshal(nv)
	if err != nil {
		return raw, true
	}

	return string(b), true
}

func (a *anonymizer) anonymizeJSONValue(base string, v any) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		changed := false

		for k, cv := range t {
			child := base + "." + k
			nk := k

			// Keys of a selected object are identifiers, as are nested keys that
			// an identifier selection addresses.
			if a.childIsIdentifier(base, k) {
				nk = a.codename(k)
				changed = true
			}

			ncv, c := a.anonymizeJSONValue(child, cv)
			changed = changed || c
			out[nk] = ncv
		}

		return out, changed
	case []any:
		out := make([]any, len(t))
		changed := false

		for i, cv := range t {
			ncv, c := a.anonymizeJSONValue(base+".["+strconv.Itoa(i)+"]", cv)
			changed = changed || c
			out[i] = ncv
		}

		return out, changed
	default:
		if s, ok := jsonScalarText(v); ok && a.matches(base) {
			return a.codename(s), true
		}

		return v, false
	}
}

func jsonScalarText(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case json.Number:
		return canonicalNumberString(string(t)), true
	case bool:
		return strconv.FormatBool(t), true
	default:
		return "", false
	}
}

// anonymizeValue replaces a value of an anonymized column with its codename.
//
// String and numeric identifiers are canonicalized to the same text before
// hashing, so a device reported as "42" in one stream and 42 in another still
// maps to a single codename.
func (a *anonymizer) anonymizeValue(v Value) Value {
	switch v.Type { //nolint:exhaustive
	case TypeString:
		return Value{Type: TypeString, String: a.codename(v.String)}
	case TypeFloat:
		return Value{Type: TypeString, String: a.codename(canonicalNumber(v))}
	case TypeBool:
		return Value{Type: TypeString, String: a.codename(strconv.FormatBool(v.Bool))}
	default:
		return v
	}
}

func canonicalNumber(v Value) string {
	s := v.RawNumber
	if s == "" {
		s = strconv.FormatFloat(v.Number, 'g', -1, 64)
	}

	return canonicalNumberString(s)
}

func canonicalNumberString(s string) string {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return s
	}

	if f == float64(int64(f)) && f >= -1<<53 && f <= 1<<53 {
		return strconv.FormatInt(int64(f), 10)
	}

	return strconv.FormatFloat(f, 'g', -1, 64)
}

// codename returns a stable irreversible pseudonym for a real identifier.
func (a *anonymizer) codename(value string) string {
	h := sha256.New()
	_, _ = h.Write(a.salt)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(value))

	return hex.EncodeToString(h.Sum(nil)[:codenameBytes])
}
