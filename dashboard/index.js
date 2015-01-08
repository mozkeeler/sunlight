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

let tsChart = new Highcharts.StockChart({
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
let top10tsChart = new Highcharts.StockChart({
  chart: {
    renderTo: "top10timeseries"
  },
  legend: commonLegend,
  tooltip: orderedTooltip,
  series: top10series,
  yAxis: {
    max: 1.0,
    min: 0.0
  }
});
let issuerCharts = {};
for (i = 0; i < topIssuers.length; i++) {
  let h1 = document.createElement("h1");
  h1.textContent = topIssuers[i];
  document.body.appendChild(h1);
  console.log("Creating div for " + topIssuers[i]);
  // Create the div
  let div = document.createElement("div");
  div.id = topIssuers[i];
  document.body.appendChild(div);
  // Create the series
  let series = scores[topIssuers[i]];
  series.push(volumes[topIssuers[i]]);
  issuerCharts[topIssuers[i]] = new Highcharts.StockChart({
    chart: {
      renderTo: topIssuers[i]
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
