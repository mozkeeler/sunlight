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
  document.getElementById("autocomplete").value = name;
  setChartLink(name);
}

function setChartLink(name) {
  let link = document.getElementById("chartlink");
  link.href = "?" + encodeURIComponent(name);
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

let months = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
  "Dec"
];

function makeExamples(examples) {
  // e.g. 'COMODO ECC Domain Validation Secure Server CA 2' has a perfect
  // score, so there are no examples of bad certificates issued by it.
  if (!examples) {
    return;
  }
  let examplesHeader = document.getElementById("examplesHeader");
  let examplesBody = document.getElementById("examplesBody");
  let exampleTypes = [];
  for (let key of Object.keys(examples)) {
    if (key.endsWith("Example") && examples[key]) {
      exampleTypes.push(key.substring(0, key.indexOf("Example")));
    }
  }
  for (let example of exampleTypes) {
    let header = document.createElement("th");
    let lastSeen = new Date(examples[example + "LastSeen"]);
    header.textContent = example + " (last seen " + lastSeen.getDate() + " " +
                         months[lastSeen.getMonth()] + " " +
                         lastSeen.getFullYear() + ")";
    examplesHeader.appendChild(header);
    let td = document.createElement("td");
    let pem = examples[example + "Example"]
                .replace(/[\r\n]/g, "")
                .replace(/-----(BEGIN|END) CERTIFICATE-----/g, "");
    let frame = document.createElement("iframe");
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

filterIssuersByIssuance();
makeChart(location.search ? decodeURIComponent(location.search.substring(1))
                          : filteredIssuers[0]);
