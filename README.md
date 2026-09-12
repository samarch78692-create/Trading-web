# TradeSmart Academy — Free Hosting + Android

Recommended deployment: Render free Web Service + PostgreSQL.

1. Put this folder in a GitHub repository.
2. On Android Chrome, open Render.
3. New → Web Service → select the repository.
4. Build: npm install
5. Start: npm start
6. Select Free.
7. Add DATABASE_URL, JWT_SECRET, OWNER_EMAIL and OWNER_PASSWORD.
8. Deploy and open the HTTPS URL.

Free web services can sleep after inactivity, so the first request after sleeping can be slower.

Android: open the HTTPS URL in Chrome and use Install app / Add to Home screen when available. A web manifest is included.

Only the server-side owner role can create/remove student accounts and add/delete lectures. Passwords are bcrypt-hashed and JWT authentication is used.

Modules:
01 Foundations
02 Halal / Haram Theory
03 Chart Reading
04 Risk & Psychology
05 Strategy Building
06 Practical Lab
07 Intermediate — Coming Soon
08 Advanced — Coming Soon

Educational/paper-practice platform only. No real-money trading features or profit promises.
