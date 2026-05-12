# Audit supply chain compromise — checklist

Procedimiento estándar ante alerta de paquete npm/pnpm/yarn comprometido.

**Cuándo usarlo:** advisory de seguridad menciona un paquete, scope o versión específica. Ej:
- `@tanstack/*` (TanStack, mayo 2026)
- `eslint-shellcheck` (abril 2026)
- `event-stream` (clásico 2018)

Aplicar este checklist en **cada repo** que el equipo mantenga, no solo el principal.

---

## 0. Info que necesitás del advisory

Antes de empezar, anotá:

- [ ] Paquete o scope afectado (ej. `@tanstack/*`)
- [ ] Versiones afectadas (rango o lista exacta)
- [ ] Fecha del ataque / publicación de versiones maliciosas
- [ ] IOCs (Indicators of Compromise):
  - Archivos sospechosos en el paquete (ej. `router_init.js`, ~2.3MB)
  - Dominios C2 / exfiltración (ej. `*.getsession.org`)
  - Strings raros en `package.json` (ej. `optionalDependencies` apuntando a `github:...`)
- [ ] Link al postmortem / advisory oficial

Sin esta info, los checks de abajo son a ciegas.

---

## 1. Checks de presencia (todos al mismo tiempo)

```bash
# 1a. Dep directa en package.json (todas las secciones)
grep -i "PAQUETE" package.json

# 1b. Dep transitiva en lockfile (elegí el que uses)
grep -ic "PAQUETE" pnpm-lock.yaml
grep -ic "PAQUETE" package-lock.json
grep -ic "PAQUETE" yarn.lock

# 1c. Carpeta en node_modules
ls node_modules/PAQUETE 2>&1
find node_modules -name "PAQUETE" -maxdepth 5 2>/dev/null

# 1d. optionalDependencies sospechosas (vector común de ataques recientes)
grep -A5 optionalDependencies package.json
```

**Si los 4 dan vacío → seguir al paso 2 (IOCs) por confirmación, después concluir negativo.**

---

## 2. IOCs específicos del incidente

Reemplazá `IOC` por lo que liste el advisory:

```bash
# Archivos sospechosos por nombre exacto
find . -name "IOC-FILENAME" -not -path "./.git/*" 2>/dev/null
# Ej. TanStack 2026-05: router_init.js (~2.3MB)
find node_modules -name "router_init.js" 2>/dev/null

# Refs a dominios C2 en código del repo + node_modules
grep -rn "IOC-DOMAIN" . --include="*.js" --include="*.json" --include="*.ts" \
  2>/dev/null | grep -v node_modules | head
# Ej. TanStack 2026-05: *.getsession.org
grep -rE "getsession\.org" node_modules --include="*.js" --include="*.json" 2>/dev/null | head

# Refs a commit IOC en optionalDependencies (TanStack vector)
grep -rE "github:tanstack/router#[a-f0-9]+" . --include="*.json" 2>/dev/null | grep -v node_modules/.cache

# Archivos anómalos por tamaño (malware tipo router_init.js ~2.3MB)
find node_modules -size +2M -name "*.js" 2>/dev/null | head -10
```

Filtrar manualmente: archivos legítimos grandes (typescript.js, drizzle-kit, codepage) no son indicio.

### Whitelist `@tanstack/*` (TanStack 2026-05)

Si el match es scope `@tanstack/*`, diferenciar:

| Familia | Estado |
|---------|--------|
| `query*`, `table*`, `form*`, `virtual*`, `store`, `start` (meta) | **Safe** — auditados, sin compromiso |
| `router`, `start-*` (start-react/start-server/etc), `pacer`, `db`, `ranger`, `time`, `react-charts` | **Verificar versión vs advisory** |

Listar matches:
```bash
grep -oE "@tanstack/[a-z-]+" package.json *lock* | sort -u
```

---

## 3. Timeline

```bash
# macOS
stat -f "%Sm" pnpm-lock.yaml package-lock.json yarn.lock 2>/dev/null
stat -f "%Sm" node_modules/.modules.yaml 2>/dev/null

# Linux
stat -c "%y" pnpm-lock.yaml package-lock.json yarn.lock 2>/dev/null
```

Comparar con **fecha del ataque**:

| Escenario | Riesgo |
|-----------|--------|
| Lockfile pre-ataque + último `install` pre-ataque | **Seguro** |
| Lockfile pre-ataque + `install` post-ataque con `--frozen-lockfile` | **Seguro** (lock fuerza versiones viejas) |
| Lockfile pre-ataque + `install` post-ataque SIN `--frozen-lockfile` | **Verificar IOCs en disco** |
| Lockfile actualizado post-ataque | **Alto** — confirmar versiones |

---

## 4. Auditoría builtin

```bash
pnpm audit --severity high 2>&1 | head -30
# o
npm audit --severity high 2>&1 | head -30
```

CVE conocido aparecerá acá si el advisory ya está en npm registry.

---

## 5. Veredicto y reporte

### Si TODO da negativo

Reportar en el thread:
```
✅ NO AFECTA — <repo-name>

| Check | Resultado |
|-------|-----------|
| Deps directas | 0 matches |
| Lockfile | 0 matches |
| node_modules | no existe |
| IOCs | 0 |
| Timeline | lockfile pre-ataque, sin install posterior |
```

**Acción preventiva opcional:** mantener `--frozen-lockfile` en CI + pin versiones exactas.

### Si HAY hits

Reportar inmediatamente en el thread con:
1. Qué se encontró exactamente (versión, archivo, dominio)
2. Cuándo se instaló (timestamp `node_modules`)
3. Confirmar/descartar ejecución del payload

**Acciones inmediatas si confirmado:**
- [ ] Desconectar host de internet
- [ ] **NO** correr `npm/pnpm/yarn install` (puede agravar)
- [ ] Rotar credenciales:
  - AWS / GCP / Azure
  - GitHub tokens (personal + fine-grained)
  - npm tokens (`~/.npmrc`)
  - SSH keys (`~/.ssh/`)
  - Tokens en `.env*` del repo
  - Cookies / sesiones del navegador
- [ ] Revocar sesiones activas en cloud providers
- [ ] Wipe + reinstall del host si se confirmó ejecución del payload (no confiar en remediación parcial)
- [ ] Auditar last 30 días de actividad en cuentas afectadas

---

## 6. No hacer durante el audit

- No correr `install` mientras auditás (puede traer malware si lockfile fue alterado)
- No editar lockfile / package.json
- No ejecutar scripts npm del repo (postinstall, prepare, etc.)
- No confiar 100% en `mtime` si host ya está comprometido (malware puede alterar timestamps)

---

## Checklist defensivo (proactivo, no reactivo)

Aplicar en cada repo del equipo:

- [ ] CI usa `pnpm install --frozen-lockfile` (o `npm ci`, `yarn install --immutable`)
- [ ] Deps críticas pineadas a versión exacta (`"fastify": "5.8.5"`, no `"^5.8.5"`)
- [ ] `pnpm install --ignore-scripts` cuando se pueda, o whitelist explícita en `pnpm.onlyBuiltDependencies`
- [ ] `.env*`, `.npmrc` con tokens NUNCA en repo
- [ ] Dependabot / Renovate con review humano (no automerge para runtime deps)
- [ ] `pnpm audit --severity high` en pipeline CI, bloquea merge
- [ ] Tokens GitHub fine-grained por repo (no personal access tokens con scope global)
- [ ] Para instalaciones puntuales sospechosas: hacerlas dentro de Docker, no en host

---

## Recursos

- Postmortem TanStack (2026-05-11): https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- Socket.dev — análisis de comportamiento de paquetes: https://socket.dev
- OWASP Dependency-Check: https://owasp.org/www-project-dependency-check/

---

## Plantilla mensaje para el hilo

```
Audit supply chain — <repo>

Advisory: <link>
Paquete: <scope/nombre>
Versiones afectadas: <lista>

Resultado: ✅ NO AFECTA / ❌ AFECTA / ⚠️ INCIERTO

Checks:
- Deps directas: <0 / lista>
- Lockfile: <0 / lista>
- node_modules: <no existe / presente>
- IOCs: <0 / lista>
- Timeline: <lockfile date> vs <ataque date>

[Si afecta] Acciones tomadas: <…>
[Si afecta] Acciones pendientes: <…>
```
