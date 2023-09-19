import idaapi
import idautils
import idc
import os
improt magic

class ELFExporterPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_MOD
    comment = "Export ELF segments"
    help = "Export ELF segments to a file"
    wanted_name = "ELF Exporter"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.export_elf_segments()

    def term(self):
        pass

   def export_elf_segments(self, export_address=None):
       base_addr = idaapi.get_imagebase()
        with open(elf_file_path, "wb") as dumpfile:
            elf_file_path = idc.AskFile(1, "*", "Choose a file to export segments")
        
        # 使用magic库检查文件类型
        file_type = magic.Magic()
        file_info = file_type.from_file(elf_file_path)
        
        if "ELF" not in file_info:
            print(f"{elf_file_path} is not an ELF file.")
            return
        
        with open(elf_file_path, "wb") as dumpfile:
    if not elf_file_path:
        return

    with open(elf_file_path, "wb") as dumpfile:
        for segment_ea in idautils.Segments():
            seg = idaapi.getseg(segment_ea)
            if seg:
                seg_start = seg.start_ea
                seg_end = seg.end_ea
                seg_size = seg_end - seg_start
                seg_offset = seg_start - base_addr

                # Ensure the segment is within the ELF image
                if seg_offset >= 0:
                    print(f"Exporting segment {seg} to file...")
                    self.dump_segment(dumpfile, seg_start, seg_size, seg_offset)

        print(f"Export completed. Segments saved to {elf_file_path}")

    if export_address:
        export_file_path = idc.AskFile(1, "*.bin", "Choose a destination file to export data")

        if not export_file_path:
            return

        segment = idaapi.getseg(export_address)
        if segment:
            seg_start = segment.start_ea
            seg_end = segment.end_ea
            seg_size = seg_end - seg_start
            seg_offset = seg_start - base_addr

            # Ensure the selected address is within the ELF image
            if seg_offset >= 0:
                with open(export_file_path, "wb") as exportfile:
                    self.dump_segment(exportfile, seg_start, seg_size, seg_offset)
                print(f"Exported data at address {hex(export_address)} to {export_file_path}")

  def run(self, arg):
    if arg:
        export_address = idc.AskLong(0, "Enter the address to export data from (hex):")
        if export_address is None:
            return
        self.export_elf_segments(export_address)
    else:
        self.export_elf_segments()


  def dump_segment(self, dumpfile, start, size, offset):
        dumpfile.seek(offset)
        for i in range(size):
            dumpfile.write(bytes([idc.get_wide_byte(start + i)]))

def PLUGIN_ENTRY():
    return ELFExporterPlugin()
