# OP-TEE Software Structure Diagrams

This note maps the `optee/twep-wr-ta/` project at three levels:

- Overview diagram: production public, direct TA smoke, and WAMR spike paths.
- File relationship diagram: source, script, and generated artifact roles.
- Function relationship diagram: direct TA smoke host/TA control flow.

Generated build outputs under `guest/`, `build/`, `host/*.o`, and `ta/*.ta`
are intentionally summarized instead of expanded.

TA-local TEEP_Agent and app Wasm execution require building the TA with
`TWEP_TA_WAMR_SPIKE_LINK=1`. The default `make -C optee/twep-wr-ta` build
leaves those paths unlinked. See `README.md` for the full build-flag table.

For a rendered SVG focused on the production `twepd -> cgo -> libtwep_wr.so
-> libteec -> TA` path, see `docs/optee_trustzone_production.svg`.

## Path Legend

| Path | Diagram meaning |
| --- | --- |
| Production public path | The user-facing TrustZone backend path: `twepd` calls `libtwep_wr.so` through `internal/twepwr`, and `libtwep_wr.so` invokes the TA through `libteec`. |
| Direct TA smoke path | The `optee_example_twep_wr_ta` smoke client calls TA private commands directly through `libteec` to validate boundary behavior quickly. |
| WAMR spike path | The regression-only `TA_TWEP_WR_CMD_WAMR_SPIKE_EXEC` command entrypoint. It shares the `TWEP_TA_WAMR_SPIKE_LINK=1` TA build with production TA WAMR, but is separate from production `twep_wr_execute`. |

## Overview Diagram

```mermaid
flowchart LR
    user["User / smoke runner"]
    qemu["OP-TEE QEMU guest"]

    subgraph repo["Repository build inputs"]
        rootbuild["repo Makefile\nbin/twepd, bin/twep-cli\nbuild/*.wasm, catalog.dev.cbor"]
        prepare["prepare-diagnose-smoke.sh\ncreates guest assets"]
        opteemake["optee/twep-wr-ta/Makefile\nbuilds REE host app and TA"]
        deploy["deploy.sh\ninstalls host app, TA, guest assets"]
    end

    subgraph ree["REE / Normal World"]
        cli["twep-cli"]
        twepd["twepd"]
        cgo["internal/twepwr\ncgo wrapper"]
        libwr["libtwep_wr.so\nplatform/trustzone backend"]
        smokeapp["optee_example_twep_wr_ta\nhost/main.c smoke client"]
        publicabi["twep_wr_public_abi_smoke\nhost/public_abi_smoke.c"]
        teec["libteec / TEEC transport"]
        state["guest state/cache bytes\ncatalog, apps, teep-agent artifacts"]
        http["HTTP / Evidence broker bytes\nhost I/O only"]
    end

    subgraph secure["Secure World / OP-TEE TA"]
        ta["twep-wr TA\ntwep_wr_ta.c"]
        storage["OP-TEE persistent objects\nREE FS secure storage"]
        wamrnote["TA-local WAMR runtime\nTWEP_TA_WAMR_SPIKE_LINK=1"]
        teep["TEEP_Agent WAMR\nCatalog / TC decisions"]
        appwasm["app WAMR\nhelloworld, calcadd, negaposi"]
        spike["WAMR spike command\nregression only"]
    end

    rootbuild --> prepare
    prepare --> deploy
    opteemake --> deploy
    user --> qemu
    deploy --> qemu

    %% Production public path.
    cli --> twepd
    twepd --> cgo
    cgo --> libwr
    libwr --> teec

    %% Public ABI smoke enters the same C ABI boundary without twepd.
    publicabi --> libwr

    %% Direct TA smoke bypasses twepd and libtwep_wr.so.
    smokeapp --> teec
    teec --> ta

    %% TA-local production runtime and regression spike are separate.
    ta --> storage
    ta --> wamrnote
    wamrnote --> teep
    teep --> appwasm
    ta --> appwasm
    ta --> spike

    state --> libwr
    libwr --> state
    ta -->|"need_host_io / RESUME_HOST_IO"| teec
    teec --> http
    http --> teec
    teec --> ta

    storage -.->|"CFG_REE_FS=y, CFG_RPMB_FS=n\nrollback protected=false"| state

    classDef prod fill:#d5e8d4,stroke:#82b366,stroke-width:2px;
    classDef smoke fill:#dae8fc,stroke:#6c8ebf,stroke-width:2px;
    classDef spike fill:#ffe6cc,stroke:#d79b00,stroke-width:2px;
    classDef secure fill:#f8cecc,stroke:#b85450,stroke-width:2px;
    class twepd,cgo,libwr,publicabi prod;
    class cli,smokeapp,teec smoke;
    class spike spike;
    class ta,teep,appwasm,storage,wamrnote secure;
```

## File Relationship Diagram

```mermaid
flowchart TB
    subgraph project["optee/twep-wr-ta/"]
        readme["README.md\nscope, command ABI, smoke list"]
        arch["ARCHITECTURE.md\nthese diagrams"]
        projectconf["project.conf\nAPP_NAME=twep_wr_ta\noptee_postrun metadata"]
        topmake["Makefile\nhost build, TA build, optional WAMR shim"]
        gitignore[".gitignore\nignored generated outputs"]

        subgraph hostdir["host/"]
            hostmake["Makefile\nbuild optee_example_twep_wr_ta"]
            hostmain["main.c\nTEEC smoke and direct TA command client"]
            publicsmoke["public_abi_smoke.c\nbuilt by prepare-diagnose-smoke.sh"]
            hostbin["optee_example_twep_wr_ta\nignored build output"]
        end

        subgraph tadir["ta/"]
            taheader["include/twep_wr_ta.h\nUUID and command IDs 0-11"]
            tac["twep_wr_ta.c\nTA entrypoints, command handlers, WAMR paths"]
            tamake["Makefile / sub.mk / Android.mk\nTA build glue"]
            tabin["*.ta, *.elf, *.map\nignored build outputs"]
        end

        subgraph wamrdir["wamr-ta/"]
            wamrcmake["CMakeLists.txt\nbuild TA-safe iwasm archive"]
            wamrplatform["platform/\nTA memory, time, log shims"]
            wamrbuild["build/wamr-ta/libiwasm.a\noptional generated archive"]
        end

        subgraph scripts["guest and smoke scripts"]
            prepare["prepare-diagnose-smoke.sh\nbuild/copy guest assets"]
            deploy["deploy.sh\ninstall into QEMU guest"]
            runner["run_trustzone_smokes.sh\nmode dispatcher"]
            diagnose["diagnose_verified_trustzone.sh\nverified diagnostics smoke"]
            provision["provision_and_diagnose_trustzone.sh\nprotected object provisioning smoke"]
            failures["protected_storage_failure_smoke.sh\nnegative storage smoke"]
        end

        subgraph generated["ignored generated guest tree"]
            guestbin["guest/bin/\ntwepd, twep-cli, public ABI smoke"]
            guestbuild["guest/build/\nTEEP_Agent, app Wasm, catalog, libtwep_wr.so"]
            guestfixtures["guest/fixtures/\nJPEG and verified-mode CBOR fixtures"]
        end
    end

    topmake --> hostmake
    topmake --> tamake
    topmake --> wamrcmake

    hostmain --> taheader
    publicsmoke --> taheader
    prepare --> publicsmoke
    tac --> taheader
    tamake --> tac
    tamake --> taheader
    wamrcmake --> wamrplatform
    topmake -.->|"TWEP_TA_WAMR_SPIKE_LINK=1\nproduction + spike WAMR"| wamrbuild
    wamrbuild -.->|"linked into TA build"| tamake

    prepare --> guestbin
    prepare --> guestbuild
    prepare --> guestfixtures
    deploy --> hostbin
    deploy --> tabin
    deploy --> guestbin
    deploy --> guestbuild
    deploy --> guestfixtures

    runner --> hostbin
    runner --> guestbin
    runner --> guestbuild
    runner --> guestfixtures
    runner --> diagnose
    runner --> provision
    runner --> failures
    projectconf --> artifacts
```

## Function Relationship Diagram

This diagram focuses on `host/main.c`, the direct TA smoke client. It does not
represent the normal `twepd` public path; use the rendered SVG and the overview
diagram above for that production connection path. Functions inside the
`#ifdef TWEP_TA_WAMR_SPIKE_LINK` block (production TEEP/app WAMR,
`cmd_wamr_spike_exec`, and most TEEP natives) are omitted when the TA is built
with the default `TWEP_TA_WAMR_SPIKE_LINK=0`.

```mermaid
flowchart TB
    subgraph host["REE host functions: host/main.c"]
        hmain["main()"]
        open["open_ta()"]
        close["close_ta()"]
        smoke["invoke_ping()\ninvoke_platform_status()\ninvoke_secure_storage_smoke()\ninvoke_random_smoke()\ninvoke_time_smoke()\ninvoke_cbor_dry_run_smoke()"]
        putget["secure_storage_put()\nsecure_storage_get()"]
        prodraw["invoke_production_raw()"]
        transport["trustzone_transport_execute()"]
        appsmoke["invoke_execute_helloworld()\ninvoke_execute_calcadd()\ninvoke_execute_negaposi()"]
        teepsmoke["invoke_teep_agent_resolve*()\ninvoke_teep_agent_hostcall_*()"]
        resumehost["invoke_host_io_resume()\nseed_host_io_pending()\ndrain_host_io_pending()"]
        spikehost["invoke_wamr_spike*()"]
        makeenv["make_execute_envelope()\nmake_teep_resolve_envelope()\nmake_resume_envelope()"]
        validate["validate_*_response()\nvalidate_*_app_output()"]
        teecinvoke["TEEC_InvokeCommand()"]
    end

    subgraph ta["Secure World functions: ta/twep_wr_ta.c"]
        tacreate["TA_CreateEntryPoint()"]
        taopen["TA_OpenSessionEntryPoint()"]
        tainvoke["TA_InvokeCommandEntryPoint()"]
        simplecmds["cmd_ping()\ncmd_get_platform_status()\ncmd_get_random()\ncmd_get_time()\ncmd_cbor_dry_run()\ncmd_measure_wasm()"]
        storagecmds["cmd_secure_storage_put()\ncmd_secure_storage_get()"]
        prodcmd["cmd_production_envelope()"]
        spikecmd["cmd_wamr_spike_exec()"]
        parseenv["parse_production_envelope()\nCBOR cursor helpers"]
        needio["build_need_host_io_response()\nbuild_need_evidence_response()"]
        resume["resume_pending_teep_live()\nbuild_resume_final_response()"]
        teepresolve["execute_teep_agent_resolve()"]
        teepnative["twep_teep_env natives\nread_file/write_file\nread_protected\nhttp_post/create_evidence\nplatform_status/random/time/log"]
        appw["TA-local app WAMR path\nensure_wamr_runtime()\nwasm_has_import_section()\ntwep_app_abi_version()\ntwep_app_main()\ntwep_app_free()"]
        appresponse["extract_stdout_view()\nbuild_execute_response()\nbuild_final_response_wrapper()"]
    end

  hmain --> open --> teecinvoke
  smoke --> teecinvoke
  putget --> teecinvoke
  prodraw --> teecinvoke
  transport --> prodraw
  appsmoke --> makeenv --> prodraw
  teepsmoke --> makeenv
  resumehost --> makeenv
  spikehost --> teecinvoke
  validate --> appsmoke
  validate --> teepsmoke
  close --> hmain

  teecinvoke --> tainvoke
  tainvoke --> simplecmds
  tainvoke --> storagecmds
  tainvoke --> prodcmd
  tainvoke --> spikecmd
  prodcmd --> parseenv
  prodcmd --> needio
  prodcmd --> resume
  prodcmd --> teepresolve
  prodcmd --> appw
  teepresolve --> teepnative
  teepresolve --> needio
  appw --> appresponse
  resume --> teepresolve
```

`cmd_measure_wasm()` is invoked from `libtwep_wr.so` `platform/trustzone`, not
from `host/main.c`. `read_protected` maps the protected object allowlist to
OP-TEE REE FS Secure Storage. Generic TEEP_Agent writes to
`teep-agent/verified-evidence-result.cbor` are rejected. The public REE Secure
Storage PUT command also rejects `verified-evidence-result.cbor`, the logical
`teep-acceptance-state.cbor` name, and both TA-internal slot names. The
dedicated D043 acceptance commit is the only path that updates the slots and
persists the positive-result object, which the final-capable reader observes
through the protected path.
