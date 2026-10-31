# Alien RPG – Chariot of the Gods

Mobilsidor för spelarna: rollpersoner, stress/hälsa, agendor och kartor bakom koder.

- `data.enc` – all källdata (rollpersoner, agendor, koder, kartbilder), krypterad med SL-koden.
- `build.mjs` – bygger `dist/`. Allt hemligt krypteras per kod (AES-GCM), inget ligger i klartext.
- `dist/` – det som publiceras. `dist/sl.html` visar alla koder (öppnas med SL-koden).

## Arbeta på en ny dator

```sh
cd alien
SL_KOD=<spelledarkoden> node crypt.mjs unlock   # data.enc -> data.mjs + maps/
# ändra i data.mjs
SL_KOD=<spelledarkoden> node build.mjs          # bygg dist/
SL_KOD=<spelledarkoden> node crypt.mjs lock     # spara ändringarna i data.enc
```

`data.mjs` och `maps/` är gitignorerade – committa `data.enc` och `dist/`.

Upplåsta koder sparas i spelarnas telefoner (localStorage) och ligger kvar även efter ombygge.
