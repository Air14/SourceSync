import ida_nalt
import ida_segment
import ida_bytes
import ida_nalt
import ida_idp

PAGE_SIZE = 0x1000

def main():
    try:
        fileName = ida_nalt.get_root_filename()
        with open(fileName, 'rb') as f:
            headerBytes = f.read(PAGE_SIZE)
    except Exception as error: 
        print("[PeHeaderGenerator] Failed to open root file named: " + fileName)
        return
    
    imageBase = ida_nalt.get_imagebase()
    if not ida_segment.add_segm(0, imageBase, imageBase + PAGE_SIZE, "HEADER", "DATA", 0):
        print("[PeHeaderGenerator] Failed to add segment")
        return
  
    segment = ida_segment.get_segm_by_name("HEADER")
    if not segment:
        print("[PeHeaderGenerator] Failed to get HEADER segment")
        return

    if ida_idp.ph.id == ida_idp.PLFM_386 and ida_idp.ph.flag & ida_idp.PR_USE64:
        ida_segment.set_segm_addressing(segment, 2)
    else:
        ida_segment.set_segm_addressing(segment, 1)
    
    ida_bytes.put_bytes(imageBase, headerBytes)
    
if __name__ == "__main__":
    main()