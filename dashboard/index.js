let months = [
  "January", "February", "March", "April", "May", "June", "July",
  "August", "September", "October", "November", "December"
];

let orderedTooltip = {
  useHTML: true,
  formatter: function() {
    let pointsSorted = this.points.slice().sort(function(pointA, pointB) {
      return pointB.y - pointA.y;
    });
    let t = new Date(this.x);
    let month = months[t.getUTCMonth()];
    let s = "<b>" + month + " " + t.getUTCFullYear() + "</b><ol>";
    $.each(pointsSorted, function(i, point) {
      let y = point.y.toFixed(3);
      if (point.series.visible) {
        s += "<li>" + point.series.name + ": " + y + "</li>";
      }
    });
    s += "</ol>";
    return s;
  }
};

let violationsTooltip = {
  useHTML: true,
  formatter: function() {
    let t = new Date(this.x);
    let month = months[t.getUTCMonth()];
    let s = "<b>" + month + " " + t.getUTCFullYear() + "</b><ul>";
    $.each(this.points, function(i, point) {
      let y = point.y;
      if (point.series.name != "Issuance Volume") {
        y = y.toFixed(3);
      }
      if (point.series.visible) {
        s += "<li>" + point.series.name + ": " + y + "</li>";
      }
    });
    s += "</ul>";
    return s;
  }
};

let commonLegend = {
  enabled: true,
  layout: "vertical",
  align: "right",
  verticalAlign: "middle",
  borderWidth: 2
};

let worstSeries = [];
let top10series = [];
for (i = 0; i < worstIssuers.length; i++) {
  worstSeries.push(timeseries[worstIssuers[i]]);
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
      tooltip: orderedTooltip,
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
      tooltip: orderedTooltip,
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
      tooltip: violationsTooltip,
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
