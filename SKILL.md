---
name: audit-repo
description: >
  Auditar un repo ante alerta de supply chain compromise en npm/pnpm/yarn.
  Verifica deps directas + transitivas + IOCs, reporta veredicto.
  Invocar cuando: alerta CVE de paquete npm, ataque tipo @tanstack/eslint-shellcheck/event-stream,
  o cuando usuario menciona "supply chain", "auditar paquete X", "afecta este repo el ataque a Y".
---

# Audit supply chain compromise

Procedimiento sistemático para verificar si un compromiso de supply chain afecta el repo actual.

## Arranque

Al invocar skill: **arrancar auditoría inmediatamente. No preguntar nada.**

1. Detectar package manager (pnpm/npm/yarn/bun) por lockfile.
2. Mostrar resumen 1-shot, 3 líneas:
   ```
   Auditando <repo> (pkg manager: <pnpm/npm/yarn/bun>)
   Advisory en contexto: <paquete + fecha> | <ninguno → sweep genérico>
   Responderá: Q1 ¿paquete afectado? Q2 ¿install en ventana? Q3 ¿IOCs en disco?
   ```
3. Ejecutar **todos** los pasos sin confirmación.
4. Reportar resultado **siempre** en formato 3-preguntas (ver "Veredicto").

### Modo targeted (advisory en contexto)
Correr pasos 1-7 de sección "Pasos" usando paquete/versiones/IOCs del contexto.

### Modo generic sweep (sin advisory)
Correr barrido genérico de supply chain — sin requerir input:

```bash
# Audit builtin
pnpm audit --severity high 2>&1 | head -40 || npm audit --severity high 2>&1 | head -40

# Postinstall/preinstall scripts en deps
grep -rE '"(pre|post)install"' node_modules/*/package.json 2>/dev/null | head -20

# Archivos JS anómalamente grandes en node_modules (malware típico)
find node_modules -name "*.js" -size +1M 2>/dev/null | head -10

# Match exacto archivos IOC conocidos (TanStack 2026-05, etc.)
find node_modules -type f \( -name "router_init.js" -o -name "init.js" -size +1M \) 2>/dev/null | head

# optionalDependencies apuntando a github: o url: (vector común)
grep -rE '"optionalDependencies"' node_modules/*/package.json 2>/dev/null | grep -E "github:|http" | head
# Refs específicas a commit IOC TanStack
grep -rE "github:tanstack/router#[a-f0-9]+" . --include="*.json" 2>/dev/null | grep -v node_modules/.cache | head

# Dominios C2 conocidos en código y node_modules (extender lista por advisory)
C2_DOMAINS="getsession\.org|npmrc-stats|exfil-"
grep -rE "$C2_DOMAINS" node_modules --include="*.js" --include="*.json" 2>/dev/null | head -10
grep -rE "$C2_DOMAINS" . --include="*.js" --include="*.ts" --include="*.json" 2>/dev/null | grep -v node_modules | head

# Paquetes known-bad recientes — flagear con detalle de familia
# @tanstack: SAFE = query*/table*/form*/virtual*/store/start (meta); RISK = router, start-* (router-derivados), pacer, db, ranger, time, react-charts
for pkg in "eslint-shellcheck" "event-stream" "ua-parser-js" "node-ipc" "colors" "rc" "coa"; do
  grep -l "\"$pkg\"" package.json *lock* 2>/dev/null
done
# @tanstack — listar TODOS los matches con su sub-paquete para diferenciar safe vs risk
grep -oE "@tanstack/[a-z-]+" package.json *lock* 2>/dev/null | sort -u

# Lockfile timeline (comparar mtime vs fechas advisory conocidas)
stat -f "%Sm %N" *lock* node_modules/.modules.yaml node_modules/.package-lock.json 2>/dev/null
# Fechas referencia: TanStack=2026-05-11, eslint-shellcheck=2026-04, etc.
# Si lockfile mtime > fecha advisory → riesgo alto, verificar IOCs en disco

# .npmrc / .env* en repo (no deberían estar)
ls -la .npmrc .env* 2>/dev/null
```

Reportar findings. Si hits → escalar a modo targeted con paquete encontrado.

**Whitelist `@tanstack`** (auditadas sin compromiso por TanStack): familias `query*`, `table*`, `form*`, `virtual*`, `store`, `start` (meta package, no `start-*`). Resto = sospechar hasta confirmar versión vs advisory.

Prohibido: preguntar paquete, versiones, IOCs, fechas. Inferir o correr genérico.

## Pasos

### 1. Identificar package manager del repo
```bash
ls package-lock.json pnpm-lock.yaml yarn.lock bun.lockb 2>/dev/null
```

### 2. Scan deps directas en `package.json`
```bash
grep -i "<paquete>" package.json
# Incluir: dependencies, devDependencies, optionalDependencies, peerDependencies
```

### 3. Scan deps transitivas en lockfile
```bash
# pnpm
grep -ic "<paquete>" pnpm-lock.yaml

# npm
grep -ic "<paquete>" package-lock.json

# yarn
grep -ic "<paquete>" yarn.lock
```

### 4. Verificar `node_modules`
```bash
ls node_modules/<paquete-o-scope> 2>&1
find node_modules -name "<paquete>" -maxdepth 5 2>/dev/null
```

### 5. IOCs específicos
Reemplazar `<IOC>` por los del advisory:

```bash
# Archivos sospechosos
find . -name "<archivo-IOC>" -not -path "./.git/*" 2>/dev/null

# Refs a dominios C2
grep -rn "<dominio>" . --include="*.js" --include="*.json" --include="*.ts" \
  2>/dev/null | grep -v node_modules | head

# Archivos anómalos por tamaño (ej. malware tipo router_init.js 2.3MB)
find node_modules -size +2M -name "*.js" 2>/dev/null | head -5
```

### 6. Timeline
```bash
# Última modificación del lockfile
stat -f "%Sm" pnpm-lock.yaml 2>/dev/null
stat -c "%y" pnpm-lock.yaml 2>/dev/null  # Linux

# Última ejecución de install
stat -f "%Sm" node_modules/.modules.yaml 2>/dev/null
stat -f "%Sm" node_modules/.package-lock.json 2>/dev/null
```

Comparar con fecha del ataque:
- Lockfile pre-ataque + sin `install` post-ataque → **seguro**
- Install post-ataque (incluso con `--frozen-lockfile`) → verificar IOCs en disco
- Lockfile actualizado post-ataque → riesgo alto

### 7. Auditoría npm builtin
```bash
pnpm audit --severity high 2>&1 | head -30
npm audit --severity high 2>&1 | head -30
```

## Veredicto

**Formato obligatorio** — responder siempre 3 preguntas, mismo orden, una línea cada una:

```
Audit supply chain — <repo>
Advisory: <link o "barrido genérico">

Q1. ¿Paquete afectado en repo?     <NO / SÍ: lista paquete@versión>
Q2. ¿Install en ventana de ataque? <NO: lockfile <fecha> / SÍ: install <fecha>>
Q3. ¿IOCs en disco?                <NO / SÍ: lista archivos/refs/dominios>

Veredicto: ✅ NO AFECTA  |  ❌ AFECTA  |  ⚠️ INCIERTO
```

### Reglas

- **NO AFECTA**: Q1=NO **y** Q3=NO. Q2 informativo.
- **AFECTA**: Q1=SÍ con versión en rango advisory, **o** Q3=SÍ con IOC confirmado.
- **INCIERTO**: Q1=SÍ pero versión no clara, o sin advisory + hits genéricos sin contexto.

### Si AFECTA — añadir bloque de remediación

```
Acciones inmediatas:
- Desconectar host de internet
- NO correr más npm/pnpm/yarn install en este host
- Rotar: AWS, GCP, K8s, Vault, GitHub tokens, npm token (~/.npmrc), SSH keys, .env*
- Revocar sesiones activas cloud providers
- Wipe + reinstall del host si payload ejecutado (postinstall corrió)
- Auditar últimos 30 días de actividad en cuentas comprometidas
```

### Si NO AFECTA — una línea preventiva

```
Preventivo: mantener --frozen-lockfile en CI + pin versiones exactas.
```

### Whitelist `@tanstack/*` (TanStack 2026-05-11)

Para clasificar matches en Q1:

| Familia | Estado |
|---------|--------|
| `query*`, `table*`, `form*`, `store`, `react-virtual`/`solid-virtual`/`vue-virtual`/`virtual-core` | **Safe** |
| `router`, `react-router`, `solid-router`, `vue-router`, `router-*`, `*-start`, `start-*`, `eslint-plugin-router`, `eslint-plugin-start`, `arktype-adapter`, `valibot-adapter`, `zod-adapter`, `history`, `nitro-v2-vite-plugin`, `virtual-file-routes` | **Verificar versión** |

Ventana ataque: **2026-05-11 19:20–19:26 UTC**. Lockfile/install fuera de esa ventana → Q2=NO.

## No hacer

- No auto-correr `pnpm install` durante audit (puede traer malware si lockfile fue alterado)
- No editar lockfile durante audit
- No ejecutar postinstall/scripts del repo
- No confiar en mtime si host ya comprometido (malware altera timestamps)
