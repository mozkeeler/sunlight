var sqliteToJSON = require('sqlite-to-json');
var sqlite3 = require('sqlite3');
var db = new sqlite3.Database('BRs.db');

console.log("var timeseries = {};\n");

function printTimeseries(timeseries) {
  var name = timeseries.name.replace(/[ \.-]/g, "_") + "_Timeseries";
  console.log("var " + name + " = " + JSON.stringify(timeseries) + ";\n");
  console.log("timeseries[\"" + timeseries.name + "\"] = " + name + ";\n");
}

function makeTimeseriesForIssuer(issuer, column, cb) {
  var timeseries = { name: issuer, data: [] };
  db.all("SELECT beginTime as t, " + column + " AS d " +
         "FROM issuerReputation WHERE issuer=\"" + issuer +
         "\" ORDER BY t", function (err, rows) {
    for (i = 0; i < rows.length; ++i) {
      timeseries.data.push([rows[i].t, rows[i].d]);
    }
    cb(timeseries);
  });
}

function completionDump(name, issuerArray) {
  console.log("var " + name + " = " + JSON.stringify(issuerArray) + ";\n");
}

// An array of issuers
var topIssuers = [];
var worstIssuers = [];
db.each("SELECT issuer, sum(rawCount) AS n FROM issuerReputation " +
        "GROUP BY issuer ORDER BY n DESC LIMIT 10;",
  function(err, row) {
    topIssuers.push(row.issuer);
    makeTimeseriesForIssuer(row.issuer, "rawScore", printTimeseries);
  },
  function() { completionDump("topIssuers", topIssuers); });

// We can't restrict the query based on aliases (e.g., SUM(col)) so make a
// subquery instead.
db.each("SELECT issuer, n FROM (SELECT issuer, rawScore AS n, " +
        "SUM(rawCount) AS s FROM issuerReputation GROUP BY issuer) " +
        "AS NEWTABLE WHERE s > 1000 AND issuer != \"\" ORDER BY n LIMIT 10;",
  function(err, row) {
    worstIssuers.push(row.issuer);
    makeTimeseriesForIssuer(row.issuer, "rawScore", printTimeseries);
  },
  function() { completionDump("worstIssuers", worstIssuers); });
