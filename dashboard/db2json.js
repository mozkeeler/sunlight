var sqliteToJSON = require('sqlite-to-json');
var sqlite3 = require('sqlite3');
var db = new sqlite3.Database('BRs.db');
var fs = require('fs');

var scorePrefixes = [
  "validPeriodTooLong",
  "deprecatedVersion",
  "deprecatedSignatureAlgorithm",
  "missingCNinSAN",
  "keyTooShort",
  "expTooSmall"
];

try {
  fs.mkdirSync("data");
} catch (e) {
  if (e.code != "EEXIST") {
    throw e;
  }
}

function escapeName(name) {
  return name.replace(/[^A-Za-z0-9]/g, "_");
}

// Dumps to the console a single timeseries of the following format:
//   name: the issuer corresponding to the timeseries
//   data: a list of [time in milliseconds, score] list pairs
// Also dumps a line that, when evaluated as javascript, inserts an entry in
// the timeseries map that associates the issuer with the data.
function printTimeseries(timeseries) {
  var name = escapeName(timeseries.name) + "_Timeseries";
  console.log("var " + name + " = " + JSON.stringify(timeseries) + ";\n");
  console.log("timeseries[\"" + timeseries.name + "\"] = " + name + ";\n");
}

function formatFloat(val) {
  return parseFloat(val.toFixed(3));
}

function makeTimeseriesForIssuer(issuer, column, cb) {
  var timeseries = { name: issuer, data: [] };
  db.each("SELECT beginTime as t, " + column + " AS d " +
          "FROM issuerReputation WHERE issuer=\"" + issuer +
          "\" ORDER BY t",
    function(err, row) {
      timeseries.data.push([row.t, formatFloat(row.d)]);
    },
    function() { cb(timeseries); });
}

// Get all of the scores of a particular type (normalized, raw) for a given
// issuer and fill in an array of { name: score, data: [[ts1, d1]] }
function makeScoresForIssuer(issuer, type, continuation) {
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
        timeseries[score].data.push([row.t, formatFloat(row[score])]);
      });
    },
    function() {
      continuation(timeseries);
    });
}

function makeVolumesForIssuer(issuer, type, continuation) {
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
      continuation(volumeSeries);
    });
}

function completionDump(name, issuerArray) {
  console.log("var " + name + " = " + JSON.stringify(issuerArray) + ";\n");
}

function initIssuerData(path) {
  if (fs.existsSync(path)) {
    fs.unlinkSync(path);
  }
}

function makeExamplesForIssuer(issuer, callback) {
  var query = "SELECT * FROM examples where issuer=\"" + issuer + "\"";
  var examples;
  db.each(query, function(err, row) {
    examples = row; // this should only happen once
  }, function() {
    callback(examples);
  });
}

// Given an issuer name and a filename to output to, dumps the JSON
// representation of a list of timeseries objects with the following
// properties:
//   name: a string representing the series (e.g. 'validPeriodTooLongRawScore')
//   data: a list of [time in milliseconds, data point value] list pairs
//   yAxis: which axis to render to (0 or 1 - differentiates scores from
//          issuance volume)
function dumpScoresVolumeAndExamplesForIssuer(issuer, issuerFilename) {
  // scoreSeries is a map of score type to Highstock data series that needs to
  // be converted to a list of Highstock data series
  makeScoresForIssuer(issuer, "RawScore", function(scoreSeries) {
    makeVolumesForIssuer(issuer, "raw", function(volumeSeries) {
      var allSeries = [];
      Object.keys(scoreSeries).forEach(function(key) {
        allSeries.push(scoreSeries[key]);
      });
      allSeries.push(volumeSeries);
      makeExamplesForIssuer(issuer, function(examples) {
        var data = { series: allSeries, examples: examples };
        fs.writeFileSync(issuerFilename, JSON.stringify(data));
      });
    });
  });
}

var allIssuers = [];
db.each("SELECT issuer, sum(rawCount) AS totalIssuance FROM issuerReputation " +
        "WHERE issuerInMozillaDB GROUP BY issuer;",
  function(err, row) {
    allIssuers.push(row);
  },
  function(err, numRows) {
    var maxIssuance = 0;
    console.log("var issuers = [");
    allIssuers.forEach(function(issuer) {
      if (issuer.totalIssuance > maxIssuance) {
        maxIssuance = issuer.totalIssuance;
      }
      console.log(JSON.stringify(issuer) + ",");
      var issuerFilename = "data/" + escapeName(issuer.issuer) + ".json";
      initIssuerData(issuerFilename);
      dumpScoresVolumeAndExamplesForIssuer(issuer.issuer, issuerFilename);
    });
    console.log("];");
    console.log("var maxIssuance = " + maxIssuance + ";");
  }
);

console.log("var timeseries = {};");
var topIssuers = [];
db.each("SELECT issuer, sum(rawCount) AS n FROM issuerReputation " +
        "WHERE issuerInMozillaDB GROUP BY issuer ORDER BY n DESC LIMIT 10;",
  function(err, row) {
    topIssuers.push(row.issuer);
    makeTimeseriesForIssuer(row.issuer, "rawScore", printTimeseries);
  },
  function() {
    completionDump("topIssuers", topIssuers);
  }
);

var worstIssuers = [];
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
  function() {
    completionDump("worstIssuers", worstIssuers);
  }
);
