// `@attome/xrm/dashboard/echarts` — the one chart library (P6, V2-D31), its own
// entry point so `import()` of it is a chunk of its own: a page with no chart
// of these kinds never downloads it. Only the parts the registry's adapters
// use are registered.
import {
  BarChart, BoxplotChart, CustomChart, HeatmapChart, LineChart, RadarChart, SankeyChart, ScatterChart, SunburstChart,
  TreemapChart,
} from 'echarts/charts';
import {
  CalendarComponent, GridComponent, MarkLineComponent, PolarComponent, RadarComponent, TooltipComponent, VisualMapComponent,
} from 'echarts/components';
import { init, use } from 'echarts/core';
import { SVGRenderer } from 'echarts/renderers';

use([
  BarChart, BoxplotChart, CustomChart, HeatmapChart, LineChart, RadarChart, SankeyChart, ScatterChart, SunburstChart,
  TreemapChart,
  CalendarComponent, GridComponent, MarkLineComponent, PolarComponent, RadarComponent, TooltipComponent, VisualMapComponent,
  SVGRenderer,
]);

export { init };
