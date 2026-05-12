# audit-repo

Auditar repo ante alerta de supply chain en npm/pnpm/yarn. Skill para Claude Code + checklist manual.

Diseñado para responder **3 preguntas** ante cualquier advisory:

1. ¿Usa el repo algún paquete afectado?
2. ¿Se corrió `install` durante la ventana del ataque?
3. ¿Hay IOCs en disco (archivos, dominios C2, refs sospechosas)?

---

## Uso rápido (Claude Code)

```
> /audit-repo
```

Arranca solo. No pregunta nada. Reporta resultado en formato:

```
Q1. Paquetes afectados en repo:    sí / no  + lista
Q2. Install en ventana de ataque:  sí / no  + fecha lockfile
Q3. IOCs en disco:                  sí / no  + detalle

Veredicto: ✅ NO AFECTA  /  ❌ AFECTA  /  ⚠️ INCIERTO
```

---

## Instalación skill

```bash
# Global
ln -s /path/to/audit-repo ~/.claude/skills/audit-repo

# O por proyecto
ln -s /path/to/audit-repo <proyecto>/.claude/skills/audit-repo
```

Verificar: `ls ~/.claude/skills/audit-repo/SKILL.md`

---

## Uso manual (sin Claude)

Ver `checklist.md`. Pegar comandos, responder 3 preguntas, reportar en thread.

Plantilla:

```
Audit supply chain — <repo>
Advisory: <link>

Q1. Paquete afectado en repo? <sí: lista / no>
Q2. Install en ventana ataque? <fecha lockfile vs fecha ataque>
Q3. IOCs en disco?             <sí: cuáles / no>

Veredicto: <NO AFECTA / AFECTA / INCIERTO>
```

---

## Ejemplo — TanStack 2026-05-11

Advisory: https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx
Ventana: 2026-05-11 19:20–19:26 UTC
Paquetes afectados: 42 del scope `@tanstack/*` (84 versiones maliciosas)

**Familias safe** (auditadas, sin compromiso): `query*`, `table*`, `form*`, `react-virtual`/`solid-virtual`/`vue-virtual`/`virtual-core`, `store`.

**Familias afectadas**: `router`, `react-router`, `solid-router`, `vue-router`, `router-*`, `*-start`, `start-*`, `eslint-plugin-router`, `eslint-plugin-start`, `arktype-adapter`, `valibot-adapter`, `zod-adapter`, `history`, `nitro-v2-vite-plugin`, `virtual-file-routes`.

IOCs:
- `optionalDependencies` → `github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c`
- Paquete ficticio `@tanstack/setup` (no existe en registry)
- Archivo `router_init.js` ~2.3 MB en raíz del tarball, no listado en `"files"`
- Helper `tanstack_runner.js`
- Exfil: `filev2.getsession.org`, `seed{1,2,3}.getsession.org`
- Payload secundario: `litter.catbox.moe/h8nc9u.js`, `litter.catbox.moe/7rrc6l.mjs`

Si hits: rotar AWS, GCP, K8s, Vault, `.npmrc`, GitHub tokens, SSH keys. No correr más `install` en el host.

---

## Estructura

```
audit-repo/
├── README.md       ← este archivo
├── SKILL.md        ← skill Claude Code
├── checklist.md    ← checklist manual
└── LICENSE
```

---

## Licencia

MIT.
