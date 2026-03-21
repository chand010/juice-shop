// ─── Relevant excerpt — replace the two methods below in your component ───────
//
// VULNERABILITY: encodeProductDescription() uses an incomplete manual HTML-
// encoding that only replaces '<' and '>'. This leaves several XSS vectors open:
//
//   - Attribute injection:   name="x" onmouseover="alert(1)" data-x="
//     → '<' and '>' are absent; the payload injects event handlers via
//       unescaped double-quotes (") and single-quotes (').
//
//   - JavaScript URI in href: href="javascript:alert(1)"
//     → no angle brackets needed; scheme survives the filter.
//
//   - Incomplete & encoding: &lt; is produced but a raw '&' in the input
//     would create malformed entities rather than being escaped to '&amp;'.
//
//   - Unicode / HTML5 named character references can bypass simple string
//     replacement in some rendering contexts.
//
// ✅ FIX: Delegate sanitization to Angular's built-in DomSanitizer instead of
//    rolling a manual encoder. Angular's sanitizer is context-aware, maintained,
//    and handles the full range of HTML injection vectors.
//
// If the description must be rendered as PLAIN TEXT (not HTML), bind it with
// Angular's text interpolation {{ product.description }} in the template —
// Angular auto-escapes all interpolated values, so no manual encoding is needed
// at all. The encodeProductDescription() call can then be removed entirely.
//
// If the description MUST contain trusted HTML markup, inject DomSanitizer and
// use sanitize(SecurityContext.HTML, value) as shown below.
//
// ─── In your component constructor / injection ────────────────────────────────
//
//   import { DomSanitizer, SecurityContext } from '@angular/platform-browser'
//
//   constructor (
//     private readonly sanitizer: DomSanitizer,
//     // ... other deps
//   ) {}
//
// ─── Replace encodeProductDescription() with: ────────────────────────────────

  encodeProductDescription (tableData: any[]) {
    // ✅ FIX: Use Angular's DomSanitizer.sanitize() which applies full
    //    context-aware HTML sanitization including attributes, event handlers,
    //    JavaScript URIs, and character encoding edge-cases.
    //
    // ❌ Before:
    //   tableData[i].description = tableData[i].description
    //     .replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    //   Only '<' and '>' were replaced, leaving attribute injection, JS URIs,
    //   unescaped quotes, and '&' as active XSS vectors.
    //
    // ✅ After: sanitize(SecurityContext.HTML, value) runs Angular's full
    //   sanitizer pipeline and returns a safe string for HTML rendering,
    //   or null if the value is null/undefined (handled below).
    for (let i = 0; i < tableData.length; i++) {
      const raw = tableData[i].description
      tableData[i].description = this.sanitizer.sanitize(SecurityContext.HTML, raw) ?? ''
    }
  }

// ─── Also import SecurityContext at the top of the file ──────────────────────
//
//   import { DomSanitizer, SecurityContext } from '@angular/platform-browser'
//
// ─── In the template, bind as innerHTML only if HTML rendering is intentional ─
//
//   <!-- Safe plain-text binding (preferred — no encoding needed at all) -->
//   <span>{{ product.description }}</span>
//
//   <!-- HTML rendering (only if rich markup is intentionally supported) -->
//   <span [innerHTML]="product.description"></span>
//
//   If you use plain {{ }} interpolation, remove the encodeProductDescription()
//   call from ngAfterViewInit() — Angular handles escaping automatically.
//
// ─── ngAfterViewInit excerpt showing where to keep/remove the call ────────────

  ngAfterViewInit () {
    const products = this.productService.search('')
    const quantities = this.quantityService.getAll()
    forkJoin([quantities, products]).subscribe({
      next: ([quantities, products]) => {
        const dataTable: TableEntry[] = []
        this.tableData = products
        this.encodeProductDescription(products) // ✅ now uses sanitizer
        for (const product of products) {
          dataTable.push({
            name: product.name,
            price: product.price,
            deluxePrice: product.deluxePrice,
            id: product.id,
            image: product.image,
            description: product.description
          })
        }
        for (const quantity of quantities) {
          const entry = dataTable.find((dataTableEntry) => {
            return dataTableEntry.id === quantity.ProductId
          })
          if (entry === undefined) {
            continue
          }
          entry.quantity = quantity.quantity
        }
        this.dataSource = new MatTableDataSource<TableEntry>(dataTable)
        for (let i = 1; i <= Math.ceil(this.dataSource.data.length / 12); i++) {
          this.pageSizeOptions.push(i * 12)
        }
        this.paginator.pageSizeOptions = this.pageSizeOptions
        this.dataSource.paginator = this.paginator
        this.gridDataSource = this.dataSource.connect()
        this.resultsLength = this.dataSource.data.length
        this.filterTable()
        this.routerSubscription = this.router.events.subscribe(() => {
          this.filterTable()
        })
        this.breakpoint = this.calculateBreakpoint(window.innerWidth)
        this.cdRef.detectChanges()
      },
      error: (err) => { console.log(err) }
    })
  }

  onResize (event: any) {
    this.breakpoint = this.calculateBreakpoint(event.target.innerWidth)
  }

  private calculateBreakpoint (width: number): number {
    if (width >= 2600) return 6
    if (width >= 1740) return 4
    if (width >= 1280) return 3
    if (width >= 850) return 2
    return 1
  }
