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
  // e.g. 'COMODO ECC Domain Validation Secure Server CA 2' has a perfect
  // score, so there are no examples of bad certificates issued by it.
  if (!examples) {
    return;
  }
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
    let cert = new X509();
    cert.readCertPEM(examples[key]);
    let signatureAlgorithm = KJUR.asn1.x509.OID.oid2name(
      ASN1HEX.hextooidstr(cert.getSignatureAlgorithmOID().getValueHex()));
    let items = [ ["version", cert.getVersion()],
                  ["signature algorithm", signatureAlgorithm],
                  ["valid from", certTimeToJSTime(cert.getNotBefore())],
                  ["valid until", certTimeToJSTime(cert.getNotAfter())] ];
    let table = createTable(items);
    td.appendChild(table);

    /*
    let certPEMArea = document.createElement("textarea");
    certPEMArea.setAttribute("rows", 30);
    certPEMArea.setAttribute("cols", 66);
    certPEMArea.setAttribute("readonly", "");
    certPEMArea.textContent = examples[key];
    td.appendChild(certPEMArea);
    */

    examplesBody.appendChild(td);
  }
}

// XXX this is the DER formatting of time - look it up
function certTimeToJSTime(certTime) {
  let year = "20" + certTime.substring(0, 2); // yeah, fix this.
  let month = certTime.substring(2, 4);
  let day = certTime.substring(4, 6);
  let hour = certTime.substring(6, 8);
  let minute = certTime.substring(8, 10);
  let second = certTime.substring(10, 12);
  return new Date(year, month, day, hour, minute, second);
}

function createTable(items) {
  let table = document.createElement("table");
  for (let pair of items) {
    let tr = document.createElement("tr");
    let td1 = document.createElement("td");
    td1.textContent = pair[0];
    let td2 = document.createElement("td");
    td2.textContent = pair[1];
    tr.appendChild(td1);
    tr.appendChild(td2);
    table.appendChild(tr);
  }
  return table;
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
