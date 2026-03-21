export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    // ✅ FIX 1: sanitize criteria — ensure it is always a plain string
    let criteria: string = req.query.q === 'undefined' ? '' : String(req.query.q ?? '')

    // ✅ FIX 2: length limit kept — good, no change needed
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)

    // ✅ FIX 3: replace raw string concatenation with parameterized query
    // ❌ Before — classic SQLi: attacker sends ' OR 1=1-- to dump entire table
    // "SELECT * FROM Products WHERE ((name LIKE '%" + criteria + "%' ..."
    // ✅ After — bind parameters, never interpolate user input into SQL
    models.sequelize.query(
      "SELECT * FROM Products WHERE ((name LIKE :search OR description LIKE :search) AND deletedAt IS NULL) ORDER BY name",
      {
        replacements: { search: `%${criteria}%` },
        type: models.sequelize.QueryTypes.SELECT
      }
    )
      .then((products: any) => {
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
