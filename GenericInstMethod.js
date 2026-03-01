
  const OFF = {
    METHOD: {
      definitionIndex: 0x??, // MethodInfo + 0x??
      methodPointer: 0x??,   // MethodInfo + 0x??
    },

    // runtime generic-method map
    CTX: {
      mask: 0x??,
      groups: 0x??,
      probeLimit: 0x??,
      groupSize: 0x??,
      entrySize: 0x??,
      entryKeyOff: 0x??,
      entryValOff: 0x??,
      keyDefIndexOff: 0x??,   // +0x??
      keyClassInstOff: 0x??,  // +0x??
      keyMethodInstOff: 0x??, // +0x??
      valMethodIndexOff: 0x??, // +0x??
      methodGlobal: 0x??,          // base + 0x??
      methodArrayOff: 0x??,        // global + 0x??
      methodCountObfOff: 0x??,     // global + 0x??
      methodCountDeobfAdd: 0x??,   // constant
    },

    GI: {
      typeArgc: 0x0, 
      typeArgv: 0x8,
    }
  };

  const PTR = Process.pointerSize;
  const NULL = ptr(0);

  function rptr(p, d = NULL) { try { return Memory.readPointer(p); } catch (_) { return d; } }
  function ru32(p, d = 0)    { try { return Memory.readU32(p); } catch (_) { return d; } }
  function rs32(p, d = -1)   { try { return Memory.readS32(p); } catch (_) { return d; } }
  function ru64(p, d = 0n)   { try { return BigInt(Memory.readU64(p).toString()); } catch (_) { return d; } }
  function cstr(p)           { try { return p.isNull() ? "" : (Memory.readCString(p) || ""); } catch (_) { return
  ""; } }

  function popCount64(x) {
    let v = x, c = 0;
    while (v) { v &= (v - 1n); c++; }
    return c;
  }

  function methodGetDefinitionIndex(methodPtr) {
    if (!methodPtr || methodPtr.isNull()) return 0xFFFFFFFF;
    return ru32(methodPtr.add(OFF.METHOD.definitionIndex), 0xFFFFFFFF);
  }

  function resolveValueToMethod(base, valuePtr) {
    if (!valuePtr || valuePtr.isNull()) return NULL;

    const methodIndex = rs32(valuePtr.add(OFF.CTX.valMethodIndexOff), -1);
    if (methodIndex < 0) return NULL;

    const global = rptr(base.add(OFF.CTX.methodGlobal), NULL);
    if (global.isNull()) return NULL;

    const cntObf = ru32(global.add(OFF.CTX.methodCountObfOff), 0);
    const methodCount = (cntObf + OFF.CTX.methodCountDeobfAdd) >>> 0;
    if ((methodIndex >>> 0) >= methodCount) return NULL;

    const methodArray = rptr(global.add(OFF.CTX.methodArrayOff), NULL);
    if (methodArray.isNull()) return NULL;

    return rptr(methodArray.add(methodIndex * PTR), NULL);
  }

  function buildMethodContextCache(base) {
    const out = new Map();

    const mask = ru64(base.add(OFF.CTX.mask), 0n);
    const groups = rptr(base.add(OFF.CTX.groups), NULL);
    if (groups.isNull() || mask === 0n) return out;

    const slotCount = Number(mask + 1n);
    if (!Number.isFinite(slotCount) || slotCount <= 0 || slotCount > 8000000) return out;

    const groupCount = Math.floor((slotCount + 63) / 64);

    for (let gi = 0; gi < groupCount; gi++) {
      const group = groups.add(gi * OFF.CTX.groupSize);
      const entries = rptr(group.add(0x0), NULL);
      const occupiedMask = ru64(group.add(0x8), 0n);
      if (entries.isNull() || occupiedMask === 0n) continue;

      for (let bit = 0; bit < 64; bit++) {
        const bitMask = 1n << BigInt(bit);
        if ((occupiedMask & bitMask) === 0n) continue;

        const lowerMask = bit === 0 ? 0n : (bitMask - 1n);
        const rank = popCount64(occupiedMask & lowerMask);

        const entry = entries.add(rank * OFF.CTX.entrySize);
        const key = rptr(entry.add(OFF.CTX.entryKeyOff), NULL);
        const val = rptr(entry.add(OFF.CTX.entryValOff), NULL);
        if (key.isNull() || val.isNull()) continue;

        const defIndex = ru32(key.add(OFF.CTX.keyDefIndexOff), 0xFFFFFFFF);
        if (defIndex === 0xFFFFFFFF) continue;

        const classInst = rptr(key.add(OFF.CTX.keyClassInstOff), NULL);
        const methodInst = rptr(key.add(OFF.CTX.keyMethodInstOff), NULL);
        const method = resolveValueToMethod(base, val);

        const k = String(defIndex);
        let arr = out.get(k);
        if (!arr) { arr = []; out.set(k, arr); }

        const ex = arr.find(x => x.classInst.equals(classInst) && x.methodInst.equals(methodInst));
        if (!ex) arr.push({ classInst, methodInst, method });
        else if (ex.method.isNull() && !method.isNull()) ex.method = method;
      }
    }

    return out;
  }

  function genericInstToString(gi, typeGetNamePtr) {
    if (!gi || gi.isNull()) return "";

    const argc = ru32(gi.add(OFF.GI.typeArgc), 0);
    if (argc === 0 || argc > 64) return "";

    const argv = rptr(gi.add(OFF.GI.typeArgv), NULL);
    if (argv.isNull()) return "";

    const parts = [];
    for (let i = 0; i < argc; i++) {
      const t = rptr(argv.add(i * PTR), NULL);
      if (t.isNull()) { parts.push("?"); continue; }
      const namePtr = typeGetNamePtr(t);
      parts.push(cstr(namePtr) || "?");
    }
    return `<${parts.join(", ")}>`;
  }

  function dumpGenericForMethod(base, methodPtr, className, methodName, typeGetNamePtr, ctxCache) {
    const defIndex = methodGetDefinitionIndex(methodPtr);
    if (defIndex === 0xFFFFFFFF) return;

    const contexts = ctxCache.get(String(defIndex)) || [];
    for (const ctx of contexts) {
      const classInst = genericInstToString(ctx.classInst, typeGetNamePtr);
      const methodInst = genericInstToString(ctx.methodInst, typeGetNamePtr);
      const fullName = `${className}${classInst}.${methodName}${methodInst}`;

      let va = 0n;
      if (!ctx.method.isNull()) {
        try { va = BigInt(Memory.readU64(ctx.method.add(OFF.METHOD.methodPointer)).toString()); } catch (_) {}
      }

      console.log(`GenericInst: ${fullName} | VA: 0x${va.toString(16)}`);
    }
  }