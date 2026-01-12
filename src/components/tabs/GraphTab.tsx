import React from 'react';
import GraphAnalysis from '@/components/graph/GraphAnalysis';
import { GraphData, GraphNode, FilterState } from '../types/adtrapper.types';

interface GraphTabProps {
  data: GraphData;
  filteredData: GraphData;
  selectedNode: GraphNode | null;
  filters: FilterState;
  darkMode: boolean;
  isStaticMode: boolean;
  setSelectedNode: (node: GraphNode | null) => void;
  setFilters: (filters: FilterState) => void;
  setStaticMode: (staticMode: boolean) => void;
  handleCanvasClick: (event: React.MouseEvent<HTMLCanvasElement>) => void;
  // Alert-centric props
  alertMode?: boolean;
  alertData?: {
    alert: any;
    relatedEvents: any[];
    affectedEntities: Array<{
      type: 'user' | 'computer' | 'ip';
      id: string;
      name: string;
    }>;
  } | null;
  onExitAlertMode?: () => void;
}

export const GraphTab: React.FC<GraphTabProps> = ({
  data,
  filteredData,
  selectedNode,
  filters,
  darkMode,
  isStaticMode,
  setSelectedNode,
  setFilters,
  setStaticMode,
  handleCanvasClick,
  alertMode = false,
  alertData,
  onExitAlertMode
}) => {
  return (
    <GraphAnalysis
      data={data}
      filteredData={filteredData}
      selectedNode={selectedNode}
      searchTerm=""
      filters={filters}
      darkMode={darkMode}
      cardClasses={darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}
      onNodeSelect={setSelectedNode}
      onSearchChange={() => {}}
      onFiltersChange={setFilters}
      onCanvasClick={handleCanvasClick}
      staticMode={isStaticMode}
      onStaticModeChange={setStaticMode}
      alertMode={alertMode}
      alertData={alertData}
      onExitAlertMode={onExitAlertMode}
    />
  );
};
