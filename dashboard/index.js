var worstSeries = [];
for (i = 0; i < worstIssuers.length; i++) {
  worstSeries.push(timeseries[worstIssuers[i]]);
}
var top10series = [];
for (i = 0; i < topIssuers.length; i++) {
  top10series.push(timeseries[topIssuers[i]]);
}

var filteredIssuers = [];
function filterIssuers() {
  // clear filteredIssuers but keep aliases to it
  while (filteredIssuers.length > 0) {
    filteredIssuers.shift();
  }
  filteredIssuers.push("Worst CAs");
  filteredIssuers.push("Top 10 CAs");

  var sliderValue = document.getElementById("minimumIssuance").value;
  var minimumIssuance = Math.ceil(Math.pow(maxIssuance, sliderValue / 100));
  var output = document.getElementById("minimumIssuanceOutput");
  output.value = minimumIssuance;

  var issuerInMozillaDB = document.getElementById("issuerInMozillaDB").checked;

  for (var index in issuers) {
    var issuer = issuers[index];
    if (issuer.totalIssuance >= minimumIssuance &&
        issuer.issuerInMozillaDB == issuerInMozillaDB) {
      filteredIssuers.push(issuer.issuer);
    }
  }
}

$('#autocomplete').autocomplete({
  source: filteredIssuers,
  minLength: 0,
  select: function(event, suggestion) {
    makeChart(suggestion.item.value);
  }
});

function escapeName(name) {
  return name.replace(/[^A-Za-z0-9]/g, "_").replace(/(^[0-9])/, "_$1");
}

function getChartData(name, continuation) {
  var escapedName = escapeName(name);
  var req = new XMLHttpRequest();
  req.open("GET", "data/" + escapedName + ".json", true);
  req.onreadystatechange = function() {
    if (req.readyState == XMLHttpRequest.DONE && req.status == 200) {
      var data = JSON.parse(req.responseText);
      continuation(data);
    }
  };
  req.send();
}

var commonLegend = {
  enabled: true,
  layout: "vertical",
  align: "right",
  verticalAlign: "middle",
  borderWidth: 2
};

function makeChart(name) {
  clearExamples();
  var commonYAxis = [{ max: 1.0, min: 0.0 }, { min: 0, opposite: false }];
  if (name == "Worst CAs") {
    new Highcharts.StockChart({
      legend: commonLegend,
      series: worstSeries,
      yAxis: commonYAxis
    });
  } else if (name == "Top 10 CAs") {
    var top10tsChart = new Highcharts.StockChart({
      legend: commonLegend,
      series: top10series,
      yAxis: commonYAxis
    });
    document.getElementById("autocomplete").value = name;
  } else {
    getChartData(name, function(seriesAndExamples) {
      new Highcharts.StockChart({
        legend: commonLegend,
        series: seriesAndExamples.series,
        yAxis: commonYAxis
      });
      makeExamples(seriesAndExamples.examples);
      var checkbox = document.getElementById("issuerInMozillaDB");
      checkbox.checked = issuers[escapeName(name)].issuerInMozillaDB;
    });
  }
  document.getElementById("autocomplete").value = name;
  var search = "?" + encodeURIComponent(name);
  history.replaceState(null, "", location.origin + location.pathname + search);
}

function clearChildren(id) {
  var element = document.getElementById(id);
  while (element.children.length > 0) {
    element.children[0].remove();
  }
}

function clearExamples() {
  clearChildren("examplesHeader");
  clearChildren("examplesBody");
}

var months = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
  "Dec"
];

function stringEndsWith(string, suffix) {
  if (suffix.length > string.length) {
    return false;
  }
  var index = string.indexOf(suffix, string.length - suffix.length);
  return index != -1;
}

function makeExamples(examples) {
  // e.g. 'COMODO ECC Domain Validation Secure Server CA 2' has a perfect
  // score, so there are no examples of bad certificates issued by it.
  if (!examples) {
    return;
  }
  var examplesHeader = document.getElementById("examplesHeader");
  var examplesBody = document.getElementById("examplesBody");
  var exampleTypes = [];
  for (var key of Object.keys(examples)) {
    if (stringEndsWith(key, "Example") && examples[key]) {
      exampleTypes.push(key.substring(0, key.indexOf("Example")));
    }
  }
  for (var example of exampleTypes) {
    var header = document.createElement("th");
    var lastSeen = new Date(examples[example + "LastSeen"]);
    header.textContent = example + " (last seen " + lastSeen.getDate() + " " +
                         months[lastSeen.getMonth()] + " " +
                         lastSeen.getFullYear() + ")";
    examplesHeader.appendChild(header);
    var td = document.createElement("td");
    var pem = examples[example + "Example"]
                .replace(/[\r\n]/g, "")
                .replace(/-----(BEGIN|END) CERTIFICATE-----/g, "");
    var frame = document.createElement("iframe");
    frame.width = "600px";
    frame.height = "600px";
    frame.src = "certsplainer/?" + pem;
    td.appendChild(frame);
    examplesBody.appendChild(td);
  }
}

// Strangely, it looks like passing in values for legend and yAxis don't work,
// so they have to be specified with each chart created.
Highcharts.setOptions({
  chart: {
    renderTo: "timeseries"
  }
});

filterIssuers();
makeChart(location.search ? decodeURIComponent(location.search.substring(1))
                          : filteredIssuers[0]);
