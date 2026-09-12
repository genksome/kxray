import os
from . import log
from . import i18n
from . import magic
from . import utils
from . import bootimg
from . import btf as btf_mod
from . import offsets
from .i18n import t

state = {
    "path": None,
    "data": None,
    "format": None,
    "magics": [],
    "bootimg": None,
    "kernel_data": None,
    "btf": None,
    "btf_all": [],
}

def clear():
    os.system("clear" if os.name == "posix" else "cls")

def header():
    print(f"  {t('app_title')}")
    print(f"  {t('app_author')}")
    print()

def pause():
    print()
    print(t("press_enter"))
    input()

def choose_language():
    clear()
    header()
    print(t("choose_lang"))
    print()
    print(t("lang_ru"))
    print(t("lang_en"))
    print()
    choice = input(f"{t('prompt_choice')}: ").strip()
    if choice == "1":
        i18n.set_lang("ru")
    else:
        i18n.set_lang("en")

def print_menu():
    clear()
    header()
    print(t("menu_title"))
    print()
    print(t("menu_open"))
    print(t("menu_analyze"))
    print(t("menu_extract"))
    print(t("menu_btf"))
    print(t("menu_export"))
    print(t("menu_settings"))
    print(t("menu_exit"))
    print()

def cmd_open():
    clear()
    header()
    print(t("menu_open"))
    print()
    path = input(f"{t('prompt_path')}: ").strip().strip('"').strip("'")
    if not path:
        log.warn(t("invalid_path"))
        pause()
        return
    if not os.path.exists(path):
        log.err(t("file_not_found", path))
        pause()
        return
    state["path"] = path
    state["data"] = utils.read_file(path)
    state["format"] = magic.identify(state["data"])
    state["magics"] = magic.scan_for_magic(state["data"], max_scan=0x1000)
    state["bootimg"] = None
    state["kernel_data"] = None
    state["btf"] = None
    state["btf_all"] = []
    clear()
    header()
    log.ok(t("open_ok", path))
    log.info(t("open_size", len(state["data"])))
    if state["format"]:
        log.ok(t("format_detected", state["format"]))
    else:
        log.warn(t("format_unknown"))
    if state["format"] == "ANDROID_BOOT":
        state["bootimg"] = bootimg.parse(state["data"])
    else:
        for off, name, m in state["magics"]:
            if name == "ANDROID_BOOT" and off > 0:
                log.warn(f"ANDROID! found at 0x{off:X}")
                state["bootimg"] = bootimg.parse(state["data"][off:])
                break
    pause()

def cmd_analyze():
    clear()
    header()
    print(t("menu_analyze"))
    print()
    if not state["data"]:
        log.warn(t("analyze_empty"))
        pause()
        return
    log.info(t("analyze_start"))
    if state["magics"]:
        log.ok(t("magic_scan"))
        for off, name, m in state["magics"][:32]:
            log.info(t("magic_at", name, off))
    else:
        log.warn(t("magic_none"))
    log.ok(t("analyze_done"))
    pause()

def _select_kernel_data(outdir):
    kernel_path = os.path.join(outdir, "kernel")
    kernel_dec_path = kernel_path + ".decompressed"
    if os.path.exists(kernel_dec_path):
        return kernel_dec_path
    if os.path.exists(kernel_path):
        return kernel_path
    return None

def _try_parse_btf(kernel_data):
    log.info(t("btf_search"))
    parsed, all_candidates = bootimg.find_btf_in_kernel(kernel_data)
    if parsed:
        state["btf"] = parsed
        state["btf_all"] = all_candidates
        log.ok(t("btf_found", len(parsed.types)))
        return True
    log.warn(t("btf_not_found"))
    return False

def cmd_extract():
    clear()
    header()
    print(t("menu_extract"))
    print()
    if not state["bootimg"]:
        log.warn(t("extract_no_bootimg"))
        pause()
        return
    outdir = input(f"{t('prompt_outdir')}: ").strip().strip('"').strip("'")
    if not outdir:
        outdir = "."
    if not os.path.isdir(outdir):
        os.makedirs(outdir, exist_ok=True)
    log.info(t("extract_start", outdir))
    log.info(t("extract_kernel"))
    bootimg.extract_kernel(state["bootimg"], os.path.join(outdir, "kernel"))
    log.info(t("extract_ramdisk"))
    bootimg.extract_ramdisk(state["bootimg"], os.path.join(outdir, "ramdisk"))
    kernel_path = _select_kernel_data(outdir)
    if kernel_path:
        state["kernel_data"] = utils.read_file(kernel_path)
        log.info(f"using kernel: {kernel_path}")
        _try_parse_btf(state["kernel_data"])
    log.ok(t("extract_done"))
    pause()

def cmd_btf():
    clear()
    header()
    print(t("menu_btf"))
    print()
    if not state["kernel_data"]:
        log.warn(t("btf_no_kernel"))
        pause()
        return
    if not state["btf"]:
        if not _try_parse_btf(state["kernel_data"]):
            pause()
            return
    b = state["btf"]
    log.info(t("btf_stats", len(b.types)))
    log.info(t("btf_strings", len(b.strings)))
    print()
    print(t("btf_menu_show"))
    print(t("btf_menu_find"))
    print(t("btf_menu_back"))
    print()
    choice = input(f"{t('prompt_choice')}: ").strip()
    if choice == "0":
        return
    elif choice == "1":
        btf_show_structs(b)
    elif choice == "2":
        btf_find_struct(b)
    else:
        log.warn(t("invalid_path"))
        pause()

def btf_show_structs(b):
    clear()
    header()
    structs = [tt for tt in b.types if tt.kind == btf_mod.KIND_STRUCT and tt.name]
    log.info(t("btf_structs", len(structs)))
    for s in structs[:128]:
        log.info(f"struct {s.name} (size={s.size_or_type}, members={len(s.members)})")
    if len(structs) > 128:
        log.info(f"... and {len(structs) - 128} more")
    pause()

def btf_find_struct(b):
    clear()
    header()
    name = input(t("btf_prompt_name") + ": ").strip()
    if not name:
        return
    s = btf_mod.find_struct(b, name)
    if not s:
        log.warn(t("btf_struct_not_found", name))
        pause()
        return
    log.ok(f"struct {s.name} (size={s.size_or_type}, members={len(s.members)})")
    for m in s.members:
        off = m.offset // 8
        log.info(f"  +0x{off:04X}  {m.name}  (type_id={m.type_id})")
    pause()

def _prompt_preset():
    print()
    print(t("preset_title"))
    print()
    print(t("preset_minimal"))
    print(t("preset_full"))
    print(t("preset_selinux"))
    print(t("preset_defex"))
    print(t("preset_kdp"))
    print(t("preset_knox"))
    print(t("preset_seccomp"))
    print(t("preset_pipe"))
    print(t("preset_umh"))
    print(t("preset_filp"))
    print(t("preset_custom"))
    print(t("preset_back"))
    print()
    choice = input(f"{t('prompt_choice')}: ").strip()
    preset_map = {
        "1": "minimal",
        "2": "full",
        "3": "selinux",
        "4": "defex",
        "5": "kdp",
        "6": "knox",
        "7": "seccomp",
        "8": "pipe",
        "9": "umh",
        "10": "filp",
        "11": "custom",
    }
    return preset_map.get(choice), choice

def cmd_export():
    clear()
    header()
    print(t("menu_export"))
    print()
    if not state["kernel_data"]:
        log.warn(t("btf_no_kernel"))
        pause()
        return
    if not state["btf"]:
        if not _try_parse_btf(state["kernel_data"]):
            pause()
            return
    kernel_version = bootimg.extract_kernel_version(state["kernel_data"])
    vermagic = bootimg.extract_vermagic(state["kernel_data"])
    if kernel_version:
        log.ok(t("kernel_version_found", kernel_version))
    else:
        log.warn(t("kernel_version_not_found"))
    if vermagic:
        log.ok(t("vermagic_found", vermagic))
    else:
        log.warn(t("vermagic_not_found"))
    preset, raw_choice = _prompt_preset()
    if not preset:
        return
    content = None
    if preset == "custom":
        log.info(t("custom_prompt"))
        log.hint(t("custom_example"))
        custom = input("> ").strip()
        if not custom:
            log.warn(t("custom_empty"))
            pause()
            return
        struct_list = [s.strip() for s in custom.split(",")]
        content = offsets.export_custom(
            state["btf"], struct_list, kernel_version, vermagic
        )
    else:
        outpath = input(f"{t('prompt_outfile')}: ").strip().strip('"').strip("'")
        if not outpath:
            outpath = f"offsets_{preset}.h"
        if os.path.isdir(outpath):
            outpath = os.path.join(outpath, f"offsets_{preset}.h")
            log.info(t("export_dir_append", outpath))
        log.info(t("export_start", outpath))
        content = offsets.export(
            state["btf"], kernel_version, vermagic, preset
        )
        utils.write_file(outpath, content.encode("utf-8"))
        log.ok(t("export_done", outpath))
        pause()
        return
    if content is not None:
        outpath = input(f"{t('prompt_outfile')}: ").strip().strip('"').strip("'")
        if not outpath:
            outpath = "offsets_custom.h"
        if os.path.isdir(outpath):
            outpath = os.path.join(outpath, "offsets_custom.h")
        log.info(t("export_start", outpath))
        utils.write_file(outpath, content.encode("utf-8"))
        log.ok(t("export_done", outpath))
    pause()

def cmd_settings():
    while True:
        clear()
        header()
        print(t("settings_title"))
        print()
        print(t("settings_lang"))
        print(t("settings_back"))
        print()
        choice = input(f"{t('prompt_choice')}: ").strip()
        if choice == "0":
            return
        elif choice == "1":
            choose_language()
        else:
            log.warn(t("invalid_path"))
            pause()

def main_menu():
    while True:
        print_menu()
        choice = input(f"{t('prompt_choice')}: ").strip()
        if choice == "0":
            clear()
            log.info(t("exit"))
            break
        elif choice == "1":
            cmd_open()
        elif choice == "2":
            cmd_analyze()
        elif choice == "3":
            cmd_extract()
        elif choice == "4":
            cmd_btf()
        elif choice == "5":
            cmd_export()
        elif choice == "6":
            cmd_settings()
        else:
            log.warn(t("invalid_path"))
            pause()

def run():
    clear()
    header()
    log.info(t("welcome"))
    choose_language()
    main_menu()
