# Cradle

A private baby tracker for feeding (nursing, bottle and solids), sleep, growth and summaries,
shared between caregivers. It's a static web app: host it on GitHub Pages, then on iPhone use
Share -> Add to Home Screen.

The data syncs through your own free Firebase project and is **end-to-end encrypted**. Google
stores only scrambled data.

## How people and babies work

- **Everyone has their own username and password.** Creating an account needs the
  **invite code**, so strangers who find the site can't sign up.
- **A baby is private to the person who adds it.** To let someone else see a baby, open the
  baby (Settings -> the baby's name) and **Share** it with their username. Only people a baby is
  shared with can see it; everyone else can't even tell it exists.
- **Anyone a baby is shared with can share it further.** The person who added the baby can remove
  people, and anyone can remove themselves.
- **Each phone logs in once** and then opens straight into the app. It only asks again if you log
  out there, or change your password on another phone. Use the home-screen icon rather than a
  Safari tab: iOS may clear a Safari tab's data after about a week without visits.

## Firebase setup (about 10 minutes, once)

You need a Google account. Everything here fits in Firebase's free "Spark" plan, so no billing
details are needed.

1. **Create the project.** Go to <https://console.firebase.google.com>, click **Create a project**
   (or **Add project**), and give it a name. Google Analytics isn't needed, so turn it off.
2. **Turn on username/password sign-in.** In the left menu go to **Build -> Authentication**,
   then **Get started**. On the **Sign-in method** tab choose **Email/Password**, turn on the
   first switch only (leave "Email link" off), and **Save**. Nobody ever types an email: the app
   turns each username into a login behind the scenes.
3. **Allow your site's address.** Still in Authentication, open **Settings -> Authorized domains**
   and **Add domain**: `<your-github-account>.github.io` (for example `mohashei.github.io`).
4. **Create the database.** Go to **Build -> Firestore Database -> Create database**. Pick a
   location near you (it can't be changed later), and choose **Start in production mode**.
5. **Install the rules.** On the Firestore **Rules** tab, delete what's there, paste in all of
   [`firestore.rules`](firestore.rules), and click **Publish**. These rules keep each baby
   visible only to the people it's shared with, and they check the invite code.
6. **Connect the app.** Click the gear icon next to "Project Overview" -> **Project settings**.
   Under **Your apps**, click the **Web** icon (`</>`), give it a nickname, leave "Firebase
   Hosting" unticked, and **Register app**. Copy the `apiKey`, `authDomain`, `projectId` and
   `appId` values into [`config.js`](config.js). These values aren't secret.
7. **Publish the site.** Push this folder to a GitHub repo, then in the repo go to **Settings ->
   Pages -> Deploy from a branch -> `main` / root**. After a minute the app is at
   `https://<your-github-account>.github.io/<repo>/`.
8. **Create your account.** Open the site, tap **Create an account**, pick a username and
   password, and enter the invite code. Then add your baby.
9. **Add the other caregivers.** Each person opens the site in Safari, uses Share -> Add to Home
   Screen, opens it from the home screen, creates their own account with the invite code, and
   tells you their username. Share the baby with that username, and it appears on their phone
   within a few seconds.

### The invite code

The rules only contain the code's SHA-256 fingerprint, never the code itself, so this public repo
doesn't give it away. To set your own code (for example, if it leaks), run this in Terminal on a Mac:

    printf %s 'your-new-code' | shasum -a 256

Then replace the 64-character value in `inviteOk()` in `firestore.rules` and publish the rules again
(step 5). Existing accounts keep working; only new sign-ups need the new code.

## What's protected and how

- **Your password never leaves your phone.** It's stretched with PBKDF2-SHA256 (600,000 rounds,
  salted with your username) and split with HKDF into:
  - a **sign-in secret**, the only thing Firebase Auth receives
  - a **key-encryption key**, which never leaves the phone
- **Every person has a key pair.** The private half is stored on the server only after being
  encrypted with your key-encryption key, and on each of your phones as a non-exportable key.
- **Every baby has its own random encryption key.** Entries, timers and the baby's name, birthday
  and sex are encrypted with AES-256-GCM under that key before they're uploaded. Sharing a baby
  seals its key to the other person's public key, so only they can open it.
- **The rules enforce who sees what.** A person can read a baby only if they're on its member
  list. Only members can add people, and only the person who added the baby can remove others.
  Data can only be written as encrypted blobs. Accounts can't be created without the invite code.
- **What Google can still see:** usernames, which usernames share a baby (but not the baby's
  name), how many entries exist and on which days, and when writes happen. It can't see what any
  entry says.
- **One limit to know:** when you share a baby, the app trusts the server to hand over the right
  public key for that username. Only someone running Google's servers could abuse that.

### If a phone is lost

Change your password in Settings. Your other phones are logged out within about an hour. Other
people are unaffected.

### If you forget your password

Nobody can reset it, because it's what unlocks your encryption keys. Create a new account (with
the invite code) and ask someone else who has the baby to share it with the new username. If
you're the only person a baby is shared with, its data is lost, so share each baby with at least
two people, or export a backup now and then (Settings -> Export a backup). The backup file is
**not** encrypted, so keep it private.

## Notes

- **Works offline.** Entries logged without signal sync when the phone reconnects.
- **Free tier.** Firebase's free plan allows 50,000 reads and 20,000 writes a day, far more than a
  few families use. It can't bill you: past the limit, syncing pauses until the next day.
- **Units** (oz/ml, lb/kg, in/cm) are set per phone in Settings.
- **Growth percentiles** use the WHO Child Growth Standards (0 to 24 months, from the CDC's data
  files) and need the baby's birth date and sex.
- **Files:** `index.html` + `styles.css` + `app.js` are the app, `who.js` is the growth data,
  `sw.js` provides offline support, and `firestore.rules` holds the database rules.
