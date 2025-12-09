# Barra di ricerca
`search-result.component.ts`

Codice vulnerabile
```ts
filterTable () {
    let queryParam: string = this.route.snapshot.queryParams.q
    if (queryParam) {
      queryParam = queryParam.trim()
      this.ngZone.runOutsideAngular(() => { // vuln-code-snippet hide-start
        this.io.socket().emit('verifyLocalXssChallenge', queryParam)
      }) // vuln-code-snippet hide-end
      this.dataSource.filter = queryParam.toLowerCase()
      this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam) // vuln-code-snippet vuln-line localXssChallenge xssBonusChallenge
      this.gridDataSource.subscribe((result: any) => {
        if (result.length === 0) {
          this.emptyState = true
        } else {
          this.emptyState = false
        }
      })
    } else {
      this.dataSource.filter = ''
      this.searchValue = undefined
      this.emptyState = false
    }
  }
```

Angular assiste i sviluppatori diffidendo gli input provenienti da utenti e quindi [implementando](https://angular.dev/best-practices/security#preventing-cross-site-scripting-xss) una rigida sanificazione dei valori da inserire nel DOM. Tuttavia, rende anche possibile la [disattivazione](https://angular.dev/best-practices/security#trusting-safe-values) del meccanismo di sanificazione automatica per scopi precisi (come inserimento di `<iframe>`) con `bypassSecurityTrust...`. In questo caso però gli sviluppatori del sito si sono **sbagliati**: la barra di ricerca non necessità di particolari funzionalità aggiuntive; essa deve solamente elaborare la stringa di ricerca e restituire i prodotti che soddisfano la stringa. Nel codice quindi viene eliminato `this.sanitizer.bypassSecurityTrustHtml(queryParam)` e sostituito con `queryParam`.

Ora avendo apportato la modifica si tenta il payload ```<iframe src="javascript:alert(`xss`)">``` nella barra di ricerca. Visualmente non si ha nessun riscontro e neppure nell'ispeziona elementi si vede alcuna traccia dell'elemento `<iframe>`. 
![Payload iframe XSS nella barra di ricerca. L'albero degli elementi mostra che l'elemento non viene inserito](images/search-bar-iframe-payload-after.png)

Ci si può domandare cosa avviene utilizzando un payload diverso, come `<img src=javascript:alert('XSS')>`. La risposta è che *Angular* immette l'elemento nel DOM con la pecularità che viene aggiunto l'attributo *unsafe* dinanzi al codice JavaScript, rendendolo del tutto inagibile e stampando in console il seguente errore:
![Errore in console con payload img](images/search-bar-img-payload-console.png)


![Payload img XSS nella barra di ricerca. L'albero degli elementi mostra che l'elemento non viene inserito](images/search-bar-img-payload-after.png)


(**PATCHED**)
Un attacco più soffisticato che si può presuppore di eseguire conoscendo il framework del sito è il [Template Injection](https://www.paloaltonetworks.com/blog/cloud-security/template-injection-vulnerabilities/). Si tratta di incorporare dentro al payload espressioni speciali come `{{}}` e far eseguire al motore JavaScript codice arbitrario e/o malizioso.

# Database Schema
`routes/search.ts`
```ts
export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`) // vuln-code-snippet vuln-line unionSqlInjectionChallenge dbSchemaChallenge
      .then(([products]: any) => {
        const dataString = JSON.stringify(products)
        if (challengeUtils.notSolved(challenges.unionSqlInjectionChallenge)) { // vuln-code-snippet hide-start
          let solved = true
          UserModel.findAll().then(data => {
            const users = utils.queryResultToJson(data)
            if (users.data?.length) {
              for (let i = 0; i < users.data.length; i++) {
                solved = solved && utils.containsOrEscaped(dataString, users.data[i].email) && utils.contains(dataString, users.data[i].password)
                if (!solved) {
                  break
                }
              }
              if (solved) {
                challengeUtils.solve(challenges.unionSqlInjectionChallenge)
              }
            }
          }).catch((error: Error) => {
            next(error)
          })
        }
        if (challengeUtils.notSolved(challenges.dbSchemaChallenge)) {
          let solved = true
          void models.sequelize.query('SELECT sql FROM sqlite_master').then(([data]: any) => {
            const tableDefinitions = utils.queryResultToJson(data)
            if (tableDefinitions.data?.length) {
              for (let i = 0; i < tableDefinitions.data.length; i++) {
                if (tableDefinitions.data[i].sql) {
                  solved = solved && utils.containsOrEscaped(dataString, tableDefinitions.data[i].sql)
                  if (!solved) {
                    break
                  }
                }
              }
              if (solved) {
                challengeUtils.solve(challenges.dbSchemaChallenge)
              }
            }
          })
        } // vuln-code-snippet hide-end
        for (let i = 0; i < products.length; i++) {
          products[i].name = req.__(products[i].name)
          products[i].description = req.__(products[i].description)
        }
        res.json(utils.queryResultToJson(products))
      }).catch((error: ErrorWithParent) => {
        next(error.parent)
      })
  }
}
```
In questa funzione che espone l'API di ricerca dei prodotti `/rest/products/search` è presente codice SQL vulnerabile, legato a un uso non corretto della libreria [Sequelize](https://sequelize.org). *Sequelize* è un ORM (Object-Relational Mapping) per *Node.js* che consente di interagire con database come MySQL e, in questo caso, SQLite.

La funzione [query()](https://sequelize.org/api/v6/class/src/sequelize.js~sequelize#instance-method-query) consente di passare un parametro stringa contenente la query SQL e restituisce una [Promise](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise) contenente il risultato. La vulnerabilità back-end del sito si trova precisamente nell'utilizzo di questo metodo: gli sviluppatori hanno costruito la stringa SQL in modo dinamico facendo un passaggio di parametro.
```ts
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```
Nel codice sopra riportato viene mostrata la query di selezione contenente il parametro `criteria`, ovvero la chiave di ricerca del prodotto. Questo viene fornito usando la formattazione `${chiave}` che corrisponde al [Template Literal](https://www.typescriptlang.org/docs/handbook/2/template-literal-types.html) di TypeScript. In questo modo la query SQL può essere costruita dinamicamente e in un modo facile, ma rende possibile l'Injection poiché il parametro non viene sanificato. L'utente malizioso, infatti, potrà eseguire un attacco di tipo `UNION` per ottenere l'intero schema del database!

Per procedere alla risoluzione di questo problema è necessario leggere la [documentazione](https://sequelize.org/docs/v6/core-concepts/raw-queries/) di Sequelize ed utilizzare correttamente le funzionalità *Replacements* oppure *Bind Parameter*  per eseguire la sanificazione della stringa proveniente dal client ed interagire nel modo più sicuro con il database.
Usando i *replacements* si crea un formato di rimpiazzamento riscrivendo il blocco `'%${criteria}%'` con `:chiave`, formando la query finale in questo modo:
`SELECT * FROM Products WHERE ((name LIKE :chiave OR description LIKE :chiave) AND deletedAt IS NULL) ORDER BY name`. Successivamente, viene richiamato il parametro nominato `:chiave` dentro l'oggetto di opzioni passato come secondo parametro a `query()`. Il risultato sarà di questo tipo:
```ts
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE :chiave OR description LIKE :chiave) AND deletedAt IS NULL) ORDER BY name`, {
      replacements: { chiave: `%${criteria}%` }
})
```

Anche la wildcard `%` (che nel LIKE di SQL corrisponde alla ricerca di tutti i pattern con la parola chiave) si trova ora attorno alla variabile `criteria`.

Proseguendo, viene eseguito il testing di Injection per assicurarsi che la vulnerabilità sia stata corretta:
![Tentativo di Injection con UNION a `rest/search?q=` da browser e visualizzazione richiesta in ZAP](images/rest-search-injection-union-after.png)

Il payload ```test')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--``` che in precedenza restituiva l'intero schema SQLite ora restituisce un array vuoto. 

# Product Tampering

`server.ts`

Il file `server.ts` è il punto di entrata principale invocato all'avvio dell'applicazione Node.js. Contiene la procedura `start()` che inizializza i servizi di WebSocket riguardanti le notifiche, le metriche di Prometheus e assegna la porta di ascolto del server. Inoltre, fa uso di **ExpressJS** per impostare gli endpoint API personalizzati. Riunisce tutte le componenti del back-end per offrire indirizzi URL all'utente finale che potrà interagire ed usufruire dei servizi esposti.
```ts
/* Baskets: Unauthorized users are not allowed to access baskets */
  app.use('/rest/basket', security.isAuthorized(), security.appendUserId())
  /* BasketItems: API only accessible for authenticated users */
  app.use('/api/BasketItems', security.isAuthorized())
  app.use('/api/BasketItems/:id', security.isAuthorized())
  // [...]
  /* Products: Only GET is allowed in order to view products */
  app.post('/api/Products', security.isAuthorized())
  app.delete('/api/Products/:id', security.denyAll())
```
Il codice sopraesposto mostra come `app` viene invocato per creare gli endpoint API e abilitare le richieste con metodi HTTP come `GET`, `POST`, `PUT`, `DELETE` a indirizzi personalizzati. Il secondo parametro delle funzioni in `app` riceve generalmente la funzione di *callback*. Questa viene utilizzata per elaborare le richieste e, nel caso più specifico, confermare l'identità dell'utente per determinarne i suoi permessi. Essa viene denominata *middleware function*, poiché agisce da tramite tra la richiesta e la risposta, gestendo l'autenticazione, il logging o gli errori.

In questo semplice caso, gli sviluppatori si sono dimenticati di assegnare i controlli di sicurezza sulla richiesta HTTP PUT di `/api/Products/:id`, consentendo a **tutti** gli utenti di modificare i prodotti a proprio piacimento. In questo modo, oltre a interrompere un servizio e procurare danno finanziario, l'utente malizioso potrebbe iniettare un payload XSS, inserendo script arbitrari nelle descrizioni dei prodotti.

Inoltre, se il middleware conteneva un controllo dei limiti (rate-limiting), con una sola riga mancante si espone il server a un attacco DoS (Denial-of-Service).

Per risolvere questa vulnerabilità occorre aggiungere il seguente blocco dentro `server.ts`:
```ts
app.route('/api/Products')
    .post(security.isAuthorized())
    .put(security.denyAll())
    .delete(security.denyAll())
app.route('/api/Products/:id')
    .post(security.isAuthorized())
    .put(security.denyAll())
    .delete(security.denyAll())
```
I servizi di `PUT` e `DELETE` vengono così rifiutati, mentre per il POST è necessario un header di autenticazione; `GET` resta abilitato normalmente per tutti. L'applicazione così modificata si rende più sicura.

![Errore di autorizzazione dopo aver tentato una richiesta `POST` su `api/Products/9](images/api-products-put-after.png)
