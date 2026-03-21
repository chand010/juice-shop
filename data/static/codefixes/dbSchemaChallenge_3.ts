export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    // ✅ FIX 1: always cast to string — prevents object/array injection
    let criteria: string = req.query.q === 'undefined' ? '' : String(req.query.q ?? '')

    // ✅ FIX 2: length limit kept
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)

    // ✅ FIX 3: removed denylist — unreliable, gives false security
    // ✅ FIX 4: parameterized query — user input never touches SQL string
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
