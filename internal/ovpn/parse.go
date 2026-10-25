package ovpn

import (
	"bytes"
	"fmt"
	"strings"
)

// This file is a line-for-line port of how OpenVPN 2.7.8 reads a --config
// file (src/openvpn/options_parse.c: read_config_file, parse_line,
// check_inline_file, read_inline_file, read_config_string, buf_parse). Every
// consumer in this package (ValidateOVPN, ParseOVPN, forEachTopLevelDirective)
// goes through parseConfig so the validator sees exactly the directive
// stream the root-run openvpn binary will see. Any divergence here is a
// validator bypass: a directive openvpn executes but the validator never
// looked at. Where an exact port isn't worth it, the parser is STRICTER than
// openvpn (it errors), never laxer.

// OpenVPN constants (options.h).
const (
	optionLineSize = 256 // OPTION_LINE_SIZE
	optionParmSize = 256 // OPTION_PARM_SIZE
	maxParms       = 16  // MAX_PARMS; parse_line is called with n = SIZE(p)-1 = MAX_PARMS
)

// directive is one option as openvpn's add_option receives it.
type directive struct {
	Name   string   // p[0], after bypass_doubledash and inline-tag stripping
	Args   []string // p[1:] (empty for inline directives; content is in Body)
	Line   int      // 1-based physical line in the original file
	Inline bool     // came from a <name>...</name> block
	Body   string   // inline block content
	// Children holds the directives of a <connection> block, parsed the way
	// openvpn's read_config_string re-parses the block body.
	Children []directive
}

// cIsSpace mirrors C isspace() in the "C" locale (openvpn never calls
// setlocale), which is what parse_line's space() and read_inline_file use.
func cIsSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// parseLine is a port of options_parse.c parse_line. It returns the
// tokens, or an error in every case openvpn reports one. Because openvpn's
// config-file parse runs at M_USAGE (fatal), every one of those errors
// makes openvpn exit, so failing here is exact rather than conservative.
func parseLine(line string) ([]string, error) {
	const (
		stInitial = iota
		stQuoted
		stUnquoted
		stDone
		stSQuoted
	)
	var (
		ret       []string
		state     = stInitial
		backslash bool
		parm      = make([]byte, 0, 64)
	)
	for i := 0; ; i++ {
		var in byte // C string terminator at i == len(line)
		if i < len(line) {
			in = line[i]
		}
		var out byte

		if !backslash && in == '\\' && state != stSQuoted {
			backslash = true
		} else {
			switch state {
			case stInitial:
				if !(in == 0 || cIsSpace(in)) {
					if in == ';' || in == '#' { // comment
						goto end
					}
					if !backslash && in == '"' {
						state = stQuoted
					} else if !backslash && in == '\'' {
						state = stSQuoted
					} else {
						out = in
						state = stUnquoted
					}
				}
			case stUnquoted:
				if !backslash && (in == 0 || cIsSpace(in)) {
					state = stDone
				} else {
					out = in
				}
			case stQuoted:
				if !backslash && in == '"' {
					state = stDone
				} else {
					out = in
				}
			case stSQuoted:
				if in == '\'' {
					state = stDone
				} else {
					out = in
				}
			}
			if state == stDone {
				ret = append(ret, string(parm))
				parm = parm[:0]
				state = stInitial
			}
			if backslash && out != 0 {
				if !(out == '\\' || out == '"' || cIsSpace(out)) {
					return nil, fmt.Errorf("bad backslash usage")
				}
			}
			backslash = false
		}

		if out != 0 {
			if len(parm) >= optionParmSize {
				return nil, fmt.Errorf("parameter too long (%d chars max)", optionParmSize)
			}
			parm = append(parm, out)
		}
		if len(ret) >= maxParms {
			break // openvpn silently drops further tokens
		}
		if i >= len(line) { // do { ... } while (*c++ != '\0')
			break
		}
	}
end:
	switch state {
	case stQuoted:
		return nil, fmt.Errorf("no closing quotation (\")")
	case stSQuoted:
		return nil, fmt.Errorf("no closing single quotation (')")
	case stInitial:
	default:
		return nil, fmt.Errorf("residual parse state")
	}
	return ret, nil
}

// bypassDoubleDash mirrors options_parse.c bypass_doubledash.
func bypassDoubleDash(s string) string {
	if len(s) >= 3 && strings.HasPrefix(s, "--") {
		return s[2:]
	}
	return s
}

// inlineTag mirrors check_inline_file's test: exactly one token of the form
// "<name>". Returns name and true when the line opens an inline block.
func inlineTag(p []string) (string, bool) {
	if len(p) != 1 {
		return "", false
	}
	a := p[0]
	if len(a) >= 1 && a[0] == '<' && a[len(a)-1] == '>' && len(a) >= 2 {
		return a[1 : len(a)-1], true
	}
	return "", false
}

// lineSource is the in_src abstraction from options_parse.c: either fgets on
// the config FILE (top level) or buf_parse on an in-memory block (the body
// of a <connection>). pos is an absolute offset into the original file so
// errors carry real line numbers.
type lineSource struct {
	data []byte
	pos  int
	end  int
	buf  bool // true: buf_parse semantics; false: fgets semantics
}

// fgets mirrors C fgets(line, size, fp): up to size-1 bytes, stopping after
// (and including) a newline. ok is false at EOF with nothing read.
func (s *lineSource) fgets(size int) (line string, start int, ok bool) {
	start = s.pos
	if s.pos >= s.end {
		return "", start, false
	}
	limit := s.pos + size - 1
	if limit > s.end {
		limit = s.end
	}
	i := s.pos
	for i < limit {
		c := s.data[i]
		i++
		if c == '\n' {
			break
		}
	}
	line = string(s.data[s.pos:i])
	s.pos = i
	return line, start, true
}

// bufParse mirrors buffer.c buf_parse(buf, '\n', line, size): reads up to
// size-1 bytes, consuming (but not returning) the delimiter; a line that
// hits the size limit is returned without consuming anything further.
// truncated reports that case.
func (s *lineSource) bufParse(size int) (line string, start int, ok, truncated bool) {
	start = s.pos
	i := s.pos
	eol := false
	for {
		if i >= s.end {
			eol = true
			break
		}
		c := s.data[i]
		if c == '\n' {
			line = string(s.data[s.pos:i])
			i++
			s.pos = i
			return line, start, true, false
		}
		if i-s.pos >= size-1 {
			truncated = true
			break
		}
		i++
	}
	line = string(s.data[s.pos:i])
	s.pos = i
	return line, start, !(eol && line == ""), truncated
}

// get mirrors in_src_get, used by read_inline_file.
func (s *lineSource) get() (line string, start int, ok, truncated bool) {
	if !s.buf {
		line, start, ok = s.fgets(optionLineSize)
		return line, start, ok, false
	}
	line, start, ok, truncated = s.bufParse(optionLineSize)
	if len(line)+1 < optionLineSize {
		line += "\n"
	}
	return line, start, ok, truncated
}

// lineNo converts an absolute byte offset into a 1-based line number. Only
// used on error paths; the hot path uses lineCounter.
func lineNo(data []byte, off int) int {
	return bytes.Count(data[:off], []byte{'\n'}) + 1
}

// lineCounter converts monotonically increasing offsets into line numbers
// in O(total) rather than O(n) per call.
type lineCounter struct {
	data      []byte
	off, line int
}

func newLineCounter(data []byte, off int) *lineCounter {
	return &lineCounter{data: data, off: off, line: lineNo(data, off)}
}

func (c *lineCounter) at(off int) int {
	if off < c.off {
		c.off, c.line = off, lineNo(c.data, off)
		return c.line
	}
	c.line += bytes.Count(c.data[c.off:off], []byte{'\n'})
	c.off = off
	return c.line
}

// readInline mirrors read_inline_file: lines are accumulated until one whose
// leading-whitespace-stripped text merely STARTS WITH the close tag (strncmp
// prefix match, so "</ca>trailing" closes the block and the trailing text is
// discarded). Returns the body and the absolute offsets of the body.
func readInline(src *lineSource, closeTag string) (body string, bodyStart, bodyEnd int, err error) {
	var sb strings.Builder
	bodyStart = src.pos
	for {
		line, start, ok, truncated := src.get()
		if !ok {
			return "", 0, 0, fmt.Errorf("end tag %s missing", closeTag)
		}
		if truncated {
			// buf_parse split a line inside a <connection> block. openvpn
			// would carry on with a mid-line fragment; refuse instead.
			return "", 0, 0, fmt.Errorf("line %d too long", lineNo(src.data, start))
		}
		if strings.HasPrefix(strings.TrimLeft(line, " \t\n\v\f\r"), closeTag) {
			return sb.String(), bodyStart, start, nil
		}
		sb.WriteString(line)
	}
}

// parseConfig parses a whole .ovpn file the way `openvpn --config FILE` does.
func parseConfig(data []byte) ([]directive, error) {
	// fgets/strlen/buf_parse all treat NUL differently (fgets keeps reading
	// but everything after the NUL is invisible to strlen; buf_parse ends the
	// line there). No legitimate profile contains one.
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return nil, fmt.Errorf("line %d: NUL byte in config", lineNo(data, i))
	}
	src := &lineSource{data: data, end: len(data)}
	lc := newLineCounter(data, 0)
	var out []directive
	first := true
	for {
		// read_config_file: char line[OPTION_LINE_SIZE + 1]; fgets(line, sizeof line, fp)
		line, start, ok := src.fgets(optionLineSize + 1)
		if !ok {
			break
		}
		ln := lc.at(start)
		if len(line) == optionLineSize {
			// openvpn: "Maximum option line length (256) exceeded" (fatal).
			return nil, fmt.Errorf("line %d: too long (max %d characters)", ln, optionLineSize-2)
		}
		if first && strings.HasPrefix(line, "\xEF\xBB\xBF") {
			line = line[3:]
		}
		first = false
		p, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", ln, err)
		}
		if len(p) == 0 {
			continue
		}
		p[0] = bypassDoubleDash(p[0])
		d := directive{Name: p[0], Args: p[1:], Line: ln}
		if tag, isInline := inlineTag(p); isInline {
			body, bStart, bEnd, err := readInline(src, "</"+tag+">")
			if err != nil {
				return nil, fmt.Errorf("line %d: <%s>: %w", ln, tag, err)
			}
			d = directive{Name: tag, Line: ln, Inline: true, Body: body}
			if tag == "connection" {
				d.Children, err = parseConnection(data, bStart, bEnd)
				if err != nil {
					return nil, err
				}
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// parseConnection mirrors read_config_string on a <connection> body, which
// openvpn re-parses line by line with buf_parse (no BOM handling, inline
// blocks read through the buffer variant of in_src_get).
func parseConnection(data []byte, start, end int) ([]directive, error) {
	src := &lineSource{data: data, pos: start, end: end, buf: true}
	lc := newLineCounter(data, start)
	var out []directive
	for {
		line, lstart, ok, truncated := src.bufParse(optionLineSize)
		if !ok {
			break
		}
		ln := lc.at(lstart)
		if truncated {
			return nil, fmt.Errorf("line %d: too long inside <connection> (max %d characters)", ln, optionLineSize-2)
		}
		p, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", ln, err)
		}
		if len(p) == 0 {
			continue
		}
		p[0] = bypassDoubleDash(p[0])
		d := directive{Name: p[0], Args: p[1:], Line: ln}
		if tag, isInline := inlineTag(p); isInline {
			body, _, _, err := readInline(src, "</"+tag+">")
			if err != nil {
				return nil, fmt.Errorf("line %d: <%s>: %w", ln, tag, err)
			}
			if tag == "connection" {
				// openvpn rejects this too (connection is not a
				// connection-block option); don't recurse.
				return nil, fmt.Errorf("line %d: nested <connection> blocks are not allowed", ln)
			}
			d = directive{Name: tag, Line: ln, Inline: true, Body: body}
		}
		out = append(out, d)
	}
	return out, nil
}

// walkDirectives visits every directive openvpn will apply, descending into
// <connection> blocks (after visiting the block itself). Stops when fn
// returns false.
func walkDirectives(ds []directive, fn func(d *directive) bool) bool {
	for i := range ds {
		if !fn(&ds[i]) {
			return false
		}
		if len(ds[i].Children) > 0 && !walkDirectives(ds[i].Children, fn) {
			return false
		}
	}
	return true
}
