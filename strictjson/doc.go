// Package strictjson decodes request bodies, query strings and signed payloads
// under the rules the specification states once and applies everywhere:
//
//   - an unrecognised member, at any nesting depth, is refused — never accepted
//     and discarded, because a 200 that lost a column is silent and unrecoverable
//   - every offending path is reported in one response, dot-separated with bare
//     decimal indices for array positions, sorted lexicographically by UTF-8 bytes
//   - a duplicate object key is refused, never resolved last-wins
//   - an integer field is a JSON integer: never a float, never a boolean, never
//     a string, and never repaired
//   - binary is standard base64, padded, validated strictly; hex is lowercase at
//     an exact length; a UUID is canonical lowercase 8-4-4-4-12
//
// None of that is available from encoding/json. DisallowUnknownFields stops at
// the first offender and yields a message rather than a path set; duplicate keys
// resolve silently to the last one; and 1.0 decodes into an integer field
// without complaint.
//
// # What this package does not decide
//
// It names no refusal code. The same structural failure is spelled
// unknown_request_field on the versioned surface, malformed_control_payload
// inside a 0x80 body, malformed_prune_payload inside a 0x81 body and
// malformed_ext_binding_payload inside a 0xBF body — one rule, four codes,
// chosen by where the bytes came from. So this package returns *UnknownFields
// and *Malformed, and the caller that knows which door the bytes arrived at maps
// them.
//
// Nor does it decide when the check runs. On the versioned surface that is after
// credential resolution and before authorisation: earlier and it is a free
// oracle for enumerating a route's accepted fields, later and a caller with both
// a malformed request and no access is told only that they lack access, and
// fixes the wrong thing.
//
// # The closed field set is the code that reads it
//
// There is no schema type to keep in step with a struct. A caller asks for the
// fields it knows, and everything it did not ask for is unknown:
//
//	body, err := strictjson.Parse(raw)
//	if err != nil { ... }
//	o := body.Root()
//	req.MemberID  = o.UUID("member_id")
//	req.ControlPK = o.Bytes("control_pk", 32)
//	if ids, ok := o.OptionalObject("key_ids"); ok {
//	        req.ControlKeyID = ids.Bytes("control_key_id", 8)
//	        ...
//	}
//	if err := body.Err(); err != nil { ... }
//
// Accessors never return early and never panic: each records its problem and
// yields a zero value, so one round trip reports every path. Err performs the
// unvisited sweep over the whole tree, so a caller that forgets to walk into a
// sub-object gets its members reported as unknown — wrong, but loudly wrong and
// in the fail-closed direction, which the first test catches.
package strictjson
