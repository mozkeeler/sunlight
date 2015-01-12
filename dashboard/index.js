let commonLegend = {
  enabled: true,
  layout: "vertical",
  align: "right",
  verticalAlign: "middle",
  borderWidth: 2
};

let worstSeries = [];
for (i = 0; i < worstIssuers.length; i++) {
  worstSeries.push(timeseries[worstIssuers[i]]);
}
let top10series = [];
for (i = 0; i < topIssuers.length; i++) {
  top10series.push(timeseries[topIssuers[i]]);
}

let select = document.getElementById("charts");
let worstCAsOption = document.createElement("option");
worstCAsOption.textContent = "Worst CAs";
select.appendChild(worstCAsOption);
let top10CAsOption = document.createElement("option");
top10CAsOption.textContent = "Top 10 CAs";
select.appendChild(top10CAsOption);

for (let issuer of topIssuers) {
  let issuerOption = document.createElement("option");
  issuerOption.textContent = issuer;
  select.appendChild(issuerOption);
}

makeChart("Worst CAs");

function chartSelected() {
  let chart = select.options[select.selectedIndex].value;
  makeChart(chart);
}

function makeChart(name) {
  if (name == "Worst CAs") {
    new Highcharts.StockChart({
      chart: {
        renderTo: "timeseries"
      },
      legend: commonLegend,
      series: worstSeries,
      yAxis: {
        max: 1.0,
        min: 0.0
      }
    });
  } else if (name == "Top 10 CAs") {
    let top10tsChart = new Highcharts.StockChart({
      chart: {
        renderTo: "timeseries"
      },
      legend: commonLegend,
      series: top10series,
      yAxis: {
        max: 1.0,
        min: 0.0
      }
    });
  } else {
    let series = scores[name].slice();
    series.push(volumes[name]);
    new Highcharts.StockChart({
      chart: {
        renderTo: "timeseries"
      },
      legend: commonLegend,
      series: series,
      yAxis: [{
        max: 1.0,
        min: 0.0
      }, {
        min: 0,
        opposite: false
      }]
    });
  }
}
