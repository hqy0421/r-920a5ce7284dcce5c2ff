package flatjsonl_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vearutop/flatjsonl/flatjsonl"
)

// anonymizeFlags returns flags for merging two device log streams.
func anonymizeFlags(t *testing.T) flatjsonl.Flags {
	t.Helper()

	f := flatjsonl.Flags{}
	f.AddSequence = true
	f.Concurrency = 1
	f.Input = "testdata/devices_a.jsonl,testdata/devices_b.jsonl"

	return f
}

// anonymizeOutputFlags returns flags writing merged streams to CSV and RAW.
func anonymizeOutputFlags(t *testing.T, csv, raw string) flatjsonl.Flags {
	t.Helper()

	f := anonymizeFlags(t)
	f.CSV = csv
	f.Raw = raw

	return f
}

func anonymizeConfig(t *testing.T, cfg string) flatjsonl.Config {
	t.Helper()

	var c flatjsonl.Config

	require.NoError(t, json.Unmarshal([]byte(cfg), &c))

	return c
}

func mustRead(t *testing.T, fn string) string {
	t.Helper()

	b, err := os.ReadFile(fn)
	require.NoError(t, err)

	return string(b)
}

// TestNewProcessor_anonymize checks that identifiers from two merged streams
// are overwritten with the same stable codenames, keeping device cardinality.
func TestNewProcessor_anonymize(t *testing.T) {
	f := anonymizeOutputFlags(t, "testdata/devices_anon.csv", "testdata/devices_anon.raw")
	t.Cleanup(func() {
		require.NoError(t, os.Remove("testdata/devices_anon.csv"))
		require.NoError(t, os.Remove("testdata/devices_anon.raw"))
	})

	cfg := anonymizeConfig(t, `{
		"anonymizeKeys": [".deviceId", ".byDevice"],
		"anonymizeSalt": "unit-test-salt"
	}`)

	proc, err := flatjsonl.NewProcessor(f, cfg, f.Inputs()...)
	require.NoError(t, err)
	require.NoError(t, proc.Process())

	csv := mustRead(t, "testdata/devices_anon.csv")

	// Original identifiers never reach the output.
	assert.NotContains(t, csv, "SN-0001")
	assert.NotContains(t, csv, "SN-0002")
	assert.NotContains(t, csv, "SN-0003")

	assert.Equal(t, `._sequence,.deviceId,.temp,.tags.[0],.tags.[1],`+
		`.byDevice.`+codenameOf(t, "SN-0001")+`.temp,.byDevice.`+codenameOf(t, "SN-0002")+`.temp,.byDevice.`+codenameOf(t, "SN-0003")+`.temp
1,`+codenameOf(t, "SN-0001")+`,21.5,x,y,30,31,
2,`+codenameOf(t, "SN-0002")+`,22.5,z,,,,
3,`+codenameOf(t, "SN-0002")+`,23.5,w,,,32,33
4,`+codenameOf(t, "SN-0001")+`,24.5,,,,,
`, csv)

	// Same-domain: the device that appears in both streams has one codename.
	ids := map[string]bool{}
	lines := strings.Split(strings.TrimSpace(csv), "\n")[1:]
	for _, l := range lines {
		ids[strings.Split(l, ",")[1]] = true
	}

	assert.Len(t, ids, 2, "two real devices must stay two distinct devices")
	assert.Contains(t, ids, codenameOf(t, "SN-0001"))
	assert.Contains(t, ids, codenameOf(t, "SN-0002"))
}

// TestNewProcessor_anonymize_transpose checks that transposed detail rows
// reference the same synthetic key as the parent rows.
func TestNewProcessor_anonymize_transpose(t *testing.T) {
	f := anonymizeOutputFlags(t, "testdata/devices_anon_transpose.csv", "")
	t.Cleanup(func() {
		require.NoError(t, os.Remove("testdata/devices_anon_transpose.csv"))
		require.NoError(t, os.Remove("testdata/devices_anon_transpose_by_device.csv"))
	})

	cfg := anonymizeConfig(t, `{
		"transpose": {".byDevice": "by_device"},
		"anonymizeKeys": [".deviceId", ".byDevice"],
		"anonymizeSalt": "unit-test-salt"
	}`)

	proc, err := flatjsonl.NewProcessor(f, cfg, f.Inputs()...)
	require.NoError(t, err)
	require.NoError(t, proc.Process())

	csv := mustRead(t, "testdata/devices_anon_transpose.csv")
	details := mustRead(t, "testdata/devices_anon_transpose_by_device.csv")

	for _, s := range []string{csv, details} {
		assert.NotContains(t, s, "SN-0001")
		assert.NotContains(t, s, "SN-0002")
		assert.NotContains(t, s, "SN-0003")
	}

	assert.Equal(t, `._sequence,.deviceId,.temp,.tags.[0],.tags.[1]
1,`+codenameOf(t, "SN-0001")+`,21.5,x,y
2,`+codenameOf(t, "SN-0002")+`,22.5,z,
3,`+codenameOf(t, "SN-0002")+`,23.5,w,
4,`+codenameOf(t, "SN-0001")+`,24.5,,
`, csv)

	// Parent join key (._sequence) and synthetic device key (._index) are
	// both present, so details can be joined back to the parent row.
	assert.Equal(t, `._sequence,._index,.temp
1,`+codenameOf(t, "SN-0001")+`,30
1,`+codenameOf(t, "SN-0002")+`,31
3,`+codenameOf(t, "SN-0002")+`,32
3,`+codenameOf(t, "SN-0003")+`,33
`, details)
}

// TestNewProcessor_anonymize_columnNames checks identifiers used as object map
// keys, which otherwise leak through generated column names.
func TestNewProcessor_anonymize_columnNames(t *testing.T) {
	f := anonymizeOutputFlags(t, "testdata/devices_anon_map.csv", "")
	t.Cleanup(func() {
		require.NoError(t, os.Remove("testdata/devices_anon_map.csv"))
	})

	cfg := anonymizeConfig(t, `{
		"anonymizeKeys": [".deviceId", ".byDevice"],
		"anonymizeSalt": "unit-test-salt"
	}`)

	proc, err := flatjsonl.NewProcessor(f, cfg, f.Inputs()...)
	require.NoError(t, err)
	require.NoError(t, proc.Process())

	csv := mustRead(t, "testdata/devices_anon_map.csv")

	assert.NotContains(t, csv, "SN-0001")
	assert.NotContains(t, csv, "SN-0002")
	assert.NotContains(t, csv, "SN-0003")

	header := strings.Split(csv, "\n")[0]
	assert.Contains(t, header, ".byDevice."+codenameOf(t, "SN-0001")+".temp")
	assert.Contains(t, header, ".byDevice."+codenameOf(t, "SN-0002")+".temp")
	assert.Contains(t, header, ".byDevice."+codenameOf(t, "SN-0003")+".temp")
}

// TestNewProcessor_anonymize_stability checks that codenames are stable across
// runs and depend on the salt.
func TestNewProcessor_anonymize_stability(t *testing.T) {
	outputs := []string{
		"testdata/devices_anon_stable1.csv",
		"testdata/devices_anon_stable2.csv",
		"testdata/devices_anon_stable3.csv",
	}

	t.Cleanup(func() {
		for _, fn := range outputs {
			require.NoError(t, os.Remove(fn))
		}
	})

	for i, cfgJSON := range []string{
		`{"anonymizeKeys": [".deviceId"], "anonymizeSalt": "salt-a"}`,
		`{"anonymizeKeys": [".deviceId"], "anonymizeSalt": "salt-a"}`,
		`{"anonymizeKeys": [".deviceId"], "anonymizeSalt": "salt-b"}`,
	} {
		f := anonymizeOutputFlags(t, outputs[i], "")
		cfg := anonymizeConfig(t, cfgJSON)

		proc, err := flatjsonl.NewProcessor(f, cfg, f.Inputs()...)
		require.NoError(t, err)
		require.NoError(t, proc.Process())
	}

	run1 := mustRead(t, outputs[0])
	run2 := mustRead(t, outputs[1])
	run3 := mustRead(t, outputs[2])

	assert.Equal(t, run1, run2, "same salt must produce stable codenames across runs")
	assert.NotEqual(t, run1, run3, "different salt must produce different codenames")
}

// TestNewProcessor_anonymize_sqlite checks that no cleartext reaches SQLite.
func TestNewProcessor_anonymize_sqlite(t *testing.T) {
	const fn = "testdata/devices_anon.sqlite"

	require.NoError(t, os.RemoveAll(fn))
	t.Cleanup(func() { require.NoError(t, os.Remove(fn)) })

	f := anonymizeFlags(t)
	f.SQLite = fn

	cfg := anonymizeConfig(t, `{
		"anonymizeKeys": [".deviceId", ".byDevice"],
		"anonymizeSalt": "unit-test-salt"
	}`)

	proc, err := flatjsonl.NewProcessor(f, cfg, f.Inputs()...)
	require.NoError(t, err)
	require.NoError(t, proc.Process())

	b := mustRead(t, fn)

	assert.NotContains(t, b, "SN-0001")
	assert.NotContains(t, b, "SN-0002")
	assert.NotContains(t, b, "SN-0003")
	assert.Contains(t, b, codenameOf(t, "SN-0001"))
}

// TestNewProcessor_anonymize_parquet checks that no cleartext reaches Parquet.
func TestNewProcessor_anonymize_parquet(t *testing.T) {
	const fn = "testdata/devices_anon.parquet"

	require.NoError(t, os.RemoveAll(fn))
	t.Cleanup(func() { require.NoError(t, os.Remove(fn)) })

	f := anonymizeFlags(t)
	f.Parquet = fn

	cfg := anonymizeConfig(t, `{
		"anonymizeKeys": [".deviceId", ".byDevice"],
		"anonymizeSalt": "unit-test-salt"
	}`)

	proc, err := flatjsonl.NewProcessor(f, cfg, f.Inputs()...)
	require.NoError(t, err)
	require.NoError(t, proc.Process())

	rows := readParquetRows(t, fn)
	require.Len(t, rows, 4)

	assert.Equal(t, codenameOf(t, "SN-0001"), rows[0][".deviceId"])
	assert.Equal(t, codenameOf(t, "SN-0002"), rows[1][".deviceId"])
	assert.Equal(t, codenameOf(t, "SN-0002"), rows[2][".deviceId"])
	assert.Equal(t, codenameOf(t, "SN-0001"), rows[3][".deviceId"])
}

// TestNewProcessor_anonymize_pg_dump checks that no cleartext reaches a PG dump.
func TestNewProcessor_anonymize_pg_dump(t *testing.T) {
	const fn = "testdata/devices_anon.pg.sql"

	require.NoError(t, os.RemoveAll(fn))
	t.Cleanup(func() { require.NoError(t, os.Remove(fn)) })

	f := anonymizeFlags(t)
	f.PGDump = fn
	f.SQLMaxCols = 500

	cfg := anonymizeConfig(t, `{
		"anonymizeKeys": [".deviceId", ".byDevice"],
		"anonymizeSalt": "unit-test-salt"
	}`)

	proc, err := flatjsonl.NewProcessor(f, cfg, f.Inputs()...)
	require.NoError(t, err)
	require.NoError(t, proc.Process())

	b := mustRead(t, fn)

	assert.NotContains(t, b, "SN-0001")
	assert.NotContains(t, b, "SN-0002")
	assert.NotContains(t, b, "SN-0003")
	assert.Contains(t, b, codenameOf(t, "SN-0001"))
}

// TestNewProcessor_anonymize_keepJSON checks identifiers inside a JSON literal
// kept as a single value, including object keys, are replaced too.
func TestNewProcessor_anonymize_keepJSON(t *testing.T) {
	const fn = "testdata/devices_anon_keepjson.csv"

	t.Cleanup(func() { require.NoError(t, os.Remove(fn)) })

	f := anonymizeOutputFlags(t, fn, "")

	cfg := anonymizeConfig(t, `{
		"keepJSON": [".byDevice"],
		"anonymizeKeys": [".deviceId", ".byDevice"],
		"anonymizeSalt": "unit-test-salt"
	}`)

	proc, err := flatjsonl.NewProcessor(f, cfg, f.Inputs()...)
	require.NoError(t, err)
	require.NoError(t, proc.Process())

	csv := mustRead(t, fn)

	assert.NotContains(t, csv, "SN-0001")
	assert.NotContains(t, csv, "SN-0002")
	assert.NotContains(t, csv, "SN-0003")

	// The literal stays valid JSON with codenamed object keys and untouched
	// non-identifier values.
	assert.Contains(t, csv, `""`+codenameOf(t, "SN-0001")+`"":{""temp"":30}`)
	assert.Contains(t, csv, `""`+codenameOf(t, "SN-0002")+`"":{""temp"":31}`)
}

// TestNewProcessor_anonymize_regex checks identifier selection by regular
// expression, both for values and for column name segments.
func TestNewProcessor_anonymize_regex(t *testing.T) {
	const fn = "testdata/devices_anon_regex.csv"

	t.Cleanup(func() { require.NoError(t, os.Remove(fn)) })

	f := anonymizeOutputFlags(t, fn, "")

	cfg := anonymizeConfig(t, `{
		"anonymizeKeysRegex": ["^\\.deviceId$", "^\\.byDevice\\.[^.]+$"],
		"anonymizeSalt": "unit-test-salt"
	}`)

	proc, err := flatjsonl.NewProcessor(f, cfg, f.Inputs()...)
	require.NoError(t, err)
	require.NoError(t, proc.Process())

	csv := mustRead(t, fn)

	assert.NotContains(t, csv, "SN-0001")
	assert.NotContains(t, csv, "SN-0002")
	assert.NotContains(t, csv, "SN-0003")
	assert.Contains(t, csv, codenameOf(t, "SN-0001"))
	assert.Contains(t, csv, ".byDevice."+codenameOf(t, "SN-0001")+".temp")
}

// codenameOf mirrors the documented codename derivation: hex of the first 96
// bits of SHA-256 over salt, a zero separator and the identifier.
func codenameOf(t *testing.T, value string) string {
	t.Helper()

	const salt = "unit-test-salt"

	h := sha256.Sum256([]byte(salt + "\x00" + value))

	return hex.EncodeToString(h[:12])
}
