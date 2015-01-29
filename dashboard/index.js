let worstSeries = [];
for (i = 0; i < worstIssuers.length; i++) {
  worstSeries.push(timeseries[worstIssuers[i]]);
}
let top10series = [];
for (i = 0; i < topIssuers.length; i++) {
  top10series.push(timeseries[topIssuers[i]]);
}

let filteredIssuers = [];
function filterIssuersByIssuance() {
  // clear filteredIssuers but keep aliases to it
  while (filteredIssuers.shift()) {}
  filteredIssuers.push("Worst CAs");
  filteredIssuers.push("Top 10 CAs");

  let sliderValue = document.getElementById("minimumIssuance").value;
  let minimumIssuance = Math.ceil(Math.pow(maxIssuance, sliderValue / 100));
  let output = document.getElementById("minimumIssuanceOutput");
  output.value = minimumIssuance;

  for (let issuer of issuers) {
    if (issuer.totalIssuance >= minimumIssuance) {
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
  return name.replace(/[^A-Za-z0-9]/g, "_");
}

function getChartData(name, continuation) {
  let escapedName = escapeName(name);
  let req = new XMLHttpRequest();
  req.open("GET", "data/" + escapedName + ".json", true);
  req.onreadystatechange = function() {
    if (req.readyState == XMLHttpRequest.DONE && req.status == 200) {
      let data = JSON.parse(req.responseText);
      continuation(data);
    }
  };
  req.send();
}

let commonLegend = {
  enabled: true,
  layout: "vertical",
  align: "right",
  verticalAlign: "middle",
  borderWidth: 2
};

function makeChart(name) {
  clearExamples();
  let commonYAxis = [{ max: 1.0, min: 0.0 }, { min: 0, opposite: false }];
  if (name == "Worst CAs") {
    new Highcharts.StockChart({
      legend: commonLegend,
      series: worstSeries,
      yAxis: commonYAxis
    });
    document.getElementById("autocomplete").value = name;
  } else if (name == "Top 10 CAs") {
    let top10tsChart = new Highcharts.StockChart({
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
    });
  }
}

function clearChildren(id) {
  let element = document.getElementById(id);
  while (element.children.length > 0) {
    element.children[0].remove();
  }
}

function clearExamples() {
  clearChildren("examplesHeader");
  clearChildren("examplesBody");
}

function makeExamples(examples) {
  let examplesHeader = document.getElementById("examplesHeader");
  let examplesBody = document.getElementById("examplesBody");
  for (let key of Object.keys(examples)) {
    if (!examples[key] || key == "issuer") {
      continue;
    }
    let header = document.createElement("th");
    header.textContent = key;
    examplesHeader.appendChild(header);
    let td = document.createElement("td");
    let cert = document.createElement("textarea");
    cert.setAttribute("rows", 30);
    cert.setAttribute("cols", 66);
    cert.setAttribute("readonly", "");
    cert.textContent = examples[key];
    td.appendChild(cert);
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

filterIssuersByIssuance();
makeChart(filteredIssuers[0]);
