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