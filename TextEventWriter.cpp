/*
   microsoft-oms-auditd-plugin

   Copyright (c) Microsoft Corporation

   All rights reserved.

   MIT License

   Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
   */

#include "TextEventWriter.h"
#include "StringUtils.h"
#include "Logger.h"

#include <cstdlib>
#include <climits>

void TextEventWriter::write_int32_field(const std::string& name, int32_t value)
{
    char buf[32];
    int len = snprintf(buf, sizeof(buf) - 1, "%d", value);
    write_raw_field(name, buf, len);
}

void TextEventWriter::write_int64_field(const std::string& name, int64_t value)
{
    char buf[32];
    int len = snprintf(buf, sizeof(buf) - 1, "%ld", value);
    write_raw_field(name, buf, len);
}

void TextEventWriter::write_string_field(const std::string& name, const std::string& value)
{
    write_raw_field(name, value.data(), value.length());
}

// ACK format: Sec:Msec:Serial\n all in fixed size HEX
ssize_t TextEventWriter::ReadAck(EventId& event_id, IReader* reader) {
	std::array<char, ((8+8+4)*2)+3> data;
	auto ret = reader->ReadAll(data.data(), data.size());
	if (ret != IO::OK) {
		return ret;
	}

	if (data[8*2] != ':' || data[(12*2)+1] != ':' || data[data.size()-1] != '\n') {
		return IO::FAILED;
	}

	data[8*2] = 0;
	data[(12*2)+1] = 0;
	data[data.size()-1] = 0;

	uint64_t sec;
	uint32_t msec;
	uint64_t serial;

	sec = strtoull(data.data(), nullptr, 16);
	msec = static_cast<uint32_t>(strtoul(&data[(8*2)+1], nullptr, 16));
	serial = strtoull(&data[(12*2)+2], nullptr, 16);

	if (sec == 0 || sec == ULLONG_MAX || msec == ULONG_MAX || serial == ULLONG_MAX) {
		return IO::FAILED;
	}

	event_id = EventId(sec, msec, serial);

	return IO::OK;
}
    
ssize_t TextEventWriter::WriteEvent(const Event& event, IWriter* writer)
{
    try {
        write_event(event);
    }
    catch (const std::exception& ex) {
        Logger::Warn("Unexpected exception while processing event: %s", ex.what());
        return IWriter::FAILED;
    }

    return IWriter::OK;
}

bool TextEventWriter::write_event(const Event& event)
{
    // Get event syscall
    std::string syscall;
    bool filtered = false;

    for (auto rec : event) {
        for (auto field : rec) {
            std::string field_name;
            field_name.assign(field.FieldNamePtr(), field.FieldNameSize());
            if (field_name == "syscall") {
                syscall = field.InterpValue();
                break;
            }
        }
        if (!syscall.empty()) {
            break;
        }
    }

    std::shared_ptr<ProcessTreeItem> p = _config._processTree->GetInfoForPid(event.Pid());

    if (syscall.empty() || !_config._filtersEngine->IsEventFiltered(syscall, p, _config.FilterFlagsMask)) {


        if (!begin_event(event))
            return false;

        int records = 0;

        for (auto record : event) {
            if (write_record(record)) {
                records++;
            }
        }

        if (records > 0) {
            end_event(event);
            return true;
        }
    }

    return false;
}

bool TextEventWriter::write_record(const EventRecord& record)
{
	int record_type = record.RecordType();
	std::string record_type_name = std::string(record.RecordTypeNamePtr(), record.RecordTypeNameSize());

	// apply record type name overrides
	if (!_config.RecordTypeNameOverrideMap.empty()) {
		auto it = _config.RecordTypeNameOverrideMap.find(record_type);
		if (it != _config.RecordTypeNameOverrideMap.end()) {
			record_type_name = it->second;
		}
	}

	// apply record type filters
	if (_config.FilterRecordTypeSet.count(record_type_name) != 0) {
		return false;
	}

	if (!begin_record(record, record_type_name)) {
		return false;
	}

	for (auto field : record) {
		write_field(field);
	}

	end_record(record);
	return true;
}

bool TextEventWriter::write_field(const EventRecordField& field)
{
    bool ret = false;

	std::string interp_name;
	std::string field_name;
	std::string raw_name;
	std::string escaped_value;
	std::string interp_value;

	field_name.assign(field.FieldNamePtr(), field.FieldNameSize());

	if (!_config.FieldNameOverrideMap.empty()) {
		auto it = _config.FieldNameOverrideMap.find(field_name);
		if (it != _config.FieldNameOverrideMap.end()) {
			raw_name.assign(it->second);
		} else {
			raw_name.assign(field_name);
		}
	} else {
		raw_name.assign(field_name);
	}

	if (!_config.InterpFieldNameMap.empty()) {
		auto it = _config.InterpFieldNameMap.find(field_name);
		if (it != _config.InterpFieldNameMap.end()) {
			interp_name.assign(it->second);
		} else {
			interp_name.assign(raw_name);
		}
	} else {
		interp_name.assign(raw_name);
	}

	if (raw_name == interp_name) {
		raw_name.append(_config.FieldSuffix);
	}

	if (field.FieldType() == field_type_t::ESCAPED || field.FieldType() == field_type_t::PROCTITLE) {
		// If the field type is FIELD_TYPE_ESCAPED, then there is no interp value in the event.
		if (_config.FilterFieldNameSet.count(interp_name) == 0) {
			switch (unescape_raw_field(interp_value, field.RawValuePtr(), field.RawValueSize())) {
				case -1: // _interp_value is identical to _raw_value
				case 0: // _raw_value was "(null)"
				default:
					write_raw_field(interp_name, field.RawValuePtr(), field.RawValueSize());
					break;
				case 1: // _raw_value was double quoted
				case 2: // _raw_value was hex encoded
					write_string_field(interp_name, interp_value);
					break;
				case 3: // _raw_value was hex encoded and decoded string needs escaping
					json_escape_string(escaped_value, interp_value.data(), interp_value.size());
					write_string_field(interp_name, escaped_value);
					break;
			}
            ret = true;
		}
	} else {
        if (field.InterpValueSize() > 0) {
			if (_config.FilterFieldNameSet.count(interp_name) == 0) {
				switch (field.FieldType()) {
					case field_type_t::SESSION:
						// Since the interpreted value for SES is also (normally) an int
						// Replace "unset" and "4294967295" with "-1"
						if ((field.InterpValueSize() == 5 && std::strncmp("unset", field.InterpValuePtr(), field.InterpValueSize()) == 0) ||
								(field.InterpValueSize() == 10 && strncmp("4294967295", field.InterpValuePtr(), field.InterpValueSize()) == 0)) {
							write_int32_field(interp_name, -1);
						} else {
							write_raw_field(interp_name, field.InterpValuePtr(), field.InterpValueSize());
						}
						break;
					default:
						write_raw_field(interp_name, field.InterpValuePtr(), field.InterpValueSize());
				}
                ret = true;
			}
			// write additional raw field
			if (_config.FilterFieldNameSet.count(raw_name) == 0) {
				write_raw_field(raw_name, field.RawValuePtr(), field.RawValueSize());
                ret = true;
			}
		} else if (_config.FilterFieldNameSet.count(interp_name) == 0) {
            if (field.FieldType() == field_type_t::UNESCAPED) {
                // fields we have created that potentially need escaping
                json_escape_string(escaped_value, field.RawValuePtr(), field.RawValueSize());
                write_string_field(interp_name, escaped_value);
            }
            else {
			    // Use interp name for raw value because there is no interp value
				write_raw_field(interp_name, field.RawValuePtr(), field.RawValueSize());
			}
            ret = true;
		}
	}
    return ret;
}
