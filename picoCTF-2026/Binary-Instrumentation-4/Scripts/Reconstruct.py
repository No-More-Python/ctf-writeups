import struct
import os
import glob

# 1. Load Header
with open("header2.bin", "rb") as f:
    header_data = f.read()

e_lfanew = struct.unpack_from("<I", header_data, 0x3c)[0]
num_sections = struct.unpack_from("<H", header_data, e_lfanew + 6)[0]
size_of_optional_header = struct.unpack_from("<H", header_data, e_lfanew + 20)[0]
optional_header_offset = e_lfanew + 24
section_header_offset = optional_header_offset + size_of_optional_header

magic = struct.unpack_from("<H", header_data, optional_header_offset)[0]
image_base = struct.unpack_from("<Q" if magic == 0x20B else "<I", header_data, optional_header_offset + (24 if magic == 0x20B else 28))[0]

# 2. Scan and load bin-ins_*.bin into Memory Address Range (Start_VA -> End_VA)
dump_ranges = []
for filepath in glob.glob("bin-ins_*.bin"):
    filename = os.path.basename(filepath)
    try:
        # Extract Hex after 'bin-ins_'
        va_hex = filename.split("_")[1].split(".")[0]
        start_va = int(va_hex, 16)
        
        with open(filepath, "rb") as f:
            data = f.read()
            
        end_va = start_va + len(data)
        dump_ranges.append({
            'filename': filename,
            'start_va': start_va,
            'end_va': end_va,
            'data': data
        })
        print(f"[*] Loaded Dump: {filename} (Range: {hex(start_va)} - {hex(end_va)})")
    except Exception as e:
        print(f"[-] Could not parse {filename}: {e}")

# 3. Calculate exe_buffer size
max_raw_end = len(header_data)
for i in range(num_sections):
    ptr = struct.unpack_from("<I", header_data, section_header_offset + i * 40 + 20)[0]
    size = struct.unpack_from("<I", header_data, section_header_offset + i * 40 + 16)[0]
    if ptr > 0:
        max_raw_end = max(max_raw_end, ptr + size)

exe_buffer = bytearray(max_raw_end)
exe_buffer[0:len(header_data)] = header_data

# 4. Map data with Dynamic Range Matching
for i in range(num_sections):
    offset = section_header_offset + i * 40
    section_name = header_data[offset:offset+8].strip(b'\x00').decode("ascii", errors='ignore')
    virtual_addr = struct.unpack_from("<I", header_data, offset+12)[0]
    raw_size = struct.unpack_from("<I", header_data, offset+16)[0]
    raw_ptr = struct.unpack_from("<I", header_data, offset+20)[0]

    if raw_ptr == 0 or raw_size == 0:
        continue

    full_va = image_base + virtual_addr
    mapped = False

    # Find which dump file memory range includes this section's full_va
    for dump in dump_ranges:
        if dump['start_va'] <= full_va < dump['end_va']:
            offset_in_bin = full_va - dump['start_va']
            slice_data = dump['data'][offset_in_bin : offset_in_bin + raw_size]
            
            if raw_ptr + len(slice_data) > len(exe_buffer):
                exe_buffer.extend(b'\x00' * (raw_ptr + len(slice_data) - len(exe_buffer)))
                        
            exe_buffer[raw_ptr : raw_ptr + len(slice_data)] = slice_data
            print(f"[+] Mapped [{section_name}] (VA: {hex(full_va)}) <- {dump['filename']} (+{hex(offset_in_bin)}) to RawPtr {hex(raw_ptr)}")
            mapped = True
            break
    if mapped == False:
        print(f"[-] [{section_name}] is not mapped")

# 5. Save file
with open("rebuilt.exe", "wb") as f_out:
    f_out.write(exe_buffer)
print("\n[+] Rebuilt file saved dynamically as rebuilt.exe")