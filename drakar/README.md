# Drakar och Demoner – Det sjunkande tornet

Mobilsidor för spelarna: rollpersoner med KP, VP, dödsslag och tillstånd, regler, samt kartor och ersättningsrollpersoner bakom koder.

- `data.enc` – källdata (rollpersoner, koder, kartbilder), krypterad med SL-koden.
- `build.mjs` – bygger `dist/`. Kartor, ersättningsrollpersoner och kodlistan krypteras per kod (AES-GCM).
- `dist/` – det som publiceras. `dist/sl.html` visar alla koder (öppnas med SL-koden).

## Arbeta på en ny dator

```sh
cd drakar
SL_KOD=<spelledarkoden> node crypt.mjs unlock   # data.enc -> data.mjs + maps/
# ändra i data.mjs
SL_KOD=<spelledarkoden> node build.mjs          # bygg dist/
SL_KOD=<spelledarkoden> node crypt.mjs lock     # spara ändringarna i data.enc
```

`data.mjs` och `maps/` är gitignorerade – committa `data.enc` och `dist/`.
