var sqliteToJSON = require('sqlite-to-json');
var sqlite3 = require('sqlite3');
var db = new sqlite3.Database('BRs.db');

var scorePrefixes = [
  "validPeriodTooLong",
  "deprecatedVersion",
  "deprecatedSignatureAlgorithm",
  "missingCNinSAN",
  "keyTooShort",
  "expTooSmall"
];

console.log("var timeseries = {};");
console.log("var scores = {};");
console.log("var volumes = {};\n");

function escapeName(name) {
  return name.replace(/[ \.\-,]/g, "_");
}

function printTimeseries(timeseries) {
  var name = escapeName(timeseries.name) + "_Timeseries";
  console.log("var " + name + " = " + JSON.stringify(timeseries) + ";\n");
  console.log("timeseries[\"" + timeseries.name + "\"] = " + name + ";\n");
}

function makeTimeseriesForIssuer(issuer, column, cb) {
  var timeseries = { name: issuer, data: [] };
  db.each("SELECT beginTime as t, " + column + " AS d " +
          "FROM issuerReputation WHERE issuer=\"" + issuer +
          "\" ORDER BY t",
    function(err, row) {
      timeseries.data.push([row.t, parseFloat(row.d.toFixed(3))]);
    },
    function() { cb(timeseries); });
}

function dumpScores(issuer, type, timeseries) {
  var scores = [];
  var scoreNames = scorePrefixes.map(function(p) { return p + type; });
  scoreNames.forEach(function(score) {
    scores.push(timeseries[score]);
  });
  console.log("scores[\"" + issuer + "\"] = " + JSON.stringify(scores));
}

function dumpVolumes(issuer, type, volumeSeries) {
  console.log("volumes[\"" + issuer + "\"] = " + JSON.stringify(volumeSeries));
}

// Get all of the scores of a particular type (normalized, raw) for a given
// issuer and fill in an array of { name: score, data: [[ts1, d1]] }
function makeScoresForIssuer(issuer, type) {
  var timeseries = {};
  // expTooSmall -> expTooSmallNormalizedScore
  var scoreNames = scorePrefixes.map(function(p) { return p + type; });
  scoreNames.map(function(score) {
    // Highstock data format
    timeseries[score] = { name: score, data: [], yAxis: 0 };
  });
  var query = "SELECT beginTime AS t, " + scoreNames.join() +
    " FROM issuerReputation WHERE issuer=\"" + issuer + "\" ORDER BY t;";
  db.each(query,
    function(err, row) {
      scoreNames.forEach(function(score) {
        timeseries[score].data.push([row.t, parseFloat(row[score].toFixed(3))]);
      });
    },
    function() {
      dumpScores(issuer, type, timeseries);
    });
}

function makeVolumesForIssuer(issuer, type) {
  var volumeSeries = { name: "Issuance Volume", data: [], yAxis: 1,
                       type: "area", zIndex: -1 };
  var volumeQuery = "SELECT " + type + "Count AS v, beginTime AS t " +
                    "FROM issuerReputation WHERE issuer=\"" + issuer + "\" " +
                    "ORDER BY t;";
  db.each(volumeQuery,
    function(err, row) {
      volumeSeries.data.push([row.t, row.v]);
    },
    function() {
      dumpVolumes(issuer, type, volumeSeries);
    });
}

function completionDump(name, issuerArray) {
  console.log("var " + name + " = " + JSON.stringify(issuerArray) + ";\n");
}

// An array of issuers
var topIssuers = [];
var worstIssuers = [];
db.each("SELECT issuer, sum(rawCount) AS n FROM issuerReputation " +
        "WHERE issuerInMozillaDB GROUP BY issuer ORDER BY n DESC LIMIT 10;",
  function(err, row) {
    topIssuers.push(row.issuer);
    makeTimeseriesForIssuer(row.issuer, "rawScore", printTimeseries);
  },
  function() {
    completionDump("topIssuers", topIssuers);
    topIssuers.forEach(function(issuer) {
      makeScoresForIssuer(issuer, "RawScore");
      makeVolumesForIssuer(issuer, "raw");
    });
  });

// We can't restrict the query based on aliases (e.g., SUM(col)) so make a
// subquery instead.
db.each("SELECT issuer, n FROM " +
           "(SELECT issuer, rawScore AS n, SUM(rawCount) AS s " +
           " FROM issuerReputation WHERE issuerInMozillaDB GROUP BY issuer) " +
        "AS NEWTABLE WHERE s > 1000 AND issuer != \"\" ORDER BY n LIMIT 10;",
  function(err, row) {
    worstIssuers.push(row.issuer);
    makeTimeseriesForIssuer(row.issuer, "rawScore", printTimeseries);
  },
  function() { completionDump("worstIssuers", worstIssuers); });
