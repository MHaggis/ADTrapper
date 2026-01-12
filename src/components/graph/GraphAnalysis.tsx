'use client'

import React, { useEffect, useRef, useState } from 'react';
import {
  Search, Filter, User, Monitor, Globe,
  Eye, EyeOff, AlertTriangle, Shield, Lock, Unlock,
  LogIn, UserPlus, Settings, Database, Wifi, WifiOff, Clock, MapPin,
  Brain, Sparkles, Flame, Layers, Info, X, Target, Activity
} from 'lucide-react';

interface Node {
  id: string;
  label: string;
  type: 'user' | 'computer' | 'ip';
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  department?: string;
  privileged?: boolean;
  enabled?: boolean;
  riskScore: number;
  os?: string;
  country?: string;
  city?: string;
  tor?: boolean;
  lastSeen?: Date;
}

interface Edge {
  source: string;
  target: string;
  type: 'login' | 'connection';
  status: 'Success' | 'Failed';
  logonType?: string;
  timestamp: Date;
  anomaly?: boolean;
}

interface Data {
  nodes: Node[];
  edges: Edge[];
  metadata: any;
  rawLogs?: any[];
}

interface FilteredData {
  nodes: Node[];
  edges: Edge[];
}

interface GraphAnalysisProps {
  data: Data;
  filteredData: FilteredData;
  selectedNode: Node | null;
  searchTerm: string;
  filters: {
    showUsers: boolean;
    showComputers: boolean;
    showIPs: boolean;
    showFailed: boolean;
    showSuccess: boolean;
    showAnomalies: boolean;
    timeRange: 'all' | string;
    selectedIPs: string[];
    selectedHostnames: string[];
    availableIPs: string[];
    availableHostnames: string[];
  };
  darkMode: boolean;
  cardClasses: string;
  onNodeSelect: (node: Node | null) => void;
  onSearchChange: (term: string) => void;
  onFiltersChange: (filters: any) => void;
  onCanvasClick: (event: React.MouseEvent<HTMLCanvasElement>) => void;
  staticMode: boolean;
  onStaticModeChange: (staticMode: boolean) => void;
  // New alert-centric props
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

const GraphAnalysis: React.FC<GraphAnalysisProps> = ({
  data,
  filteredData,
  selectedNode,
  searchTerm,
  filters,
  darkMode,
  cardClasses,
  onNodeSelect,
  onSearchChange,
  onFiltersChange,
  onCanvasClick,
  staticMode,
  onStaticModeChange,
  alertMode = false,
  alertData,
  onExitAlertMode
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // Render alert-specific graph visualization
  const renderAlertGraph = (ctx: CanvasRenderingContext2D, canvas: HTMLCanvasElement, alertData: any) => {
    const { alert, affectedEntities, relatedEvents } = alertData;

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Create alert-centric layout
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;

    // Alert node in center
    const alertNode = {
      x: centerX,
      y: centerY - 50,
      label: alert.title || 'Alert',
      type: 'alert',
      severity: alert.severity
    };

    // Position affected entities around the alert
    const entityNodes = affectedEntities.map((entity: any, index: number) => {
      const angle = (index / affectedEntities.length) * 2 * Math.PI;
      const radius = 150;
      return {
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius + 50,
        label: entity.name,
        type: entity.type,
        id: entity.id
      };
    });

    // Draw alert node
    const alertRadius = 30;
    const alertGradient = ctx.createRadialGradient(
      alertNode.x, alertNode.y, 0,
      alertNode.x, alertNode.y, alertRadius
    );

    const alertColor = alert.severity === 'critical' ? '#dc2626' :
                      alert.severity === 'high' ? '#f59e0b' :
                      alert.severity === 'medium' ? '#f59e0b' : '#6b7280';

    alertGradient.addColorStop(0, alertColor);
    alertGradient.addColorStop(1, darkMode ? '#1f2937' : '#f8fafc');

    ctx.beginPath();
    ctx.arc(alertNode.x, alertNode.y, alertRadius, 0, 2 * Math.PI);
    ctx.fillStyle = alertGradient;
    ctx.fill();
    ctx.strokeStyle = darkMode ? '#374151' : '#e5e7eb';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Alert icon
    ctx.fillStyle = '#ffffff';
    ctx.font = `${alertRadius * 0.6}px Arial`;
    ctx.textAlign = 'center';
    ctx.fillText('🚨', alertNode.x, alertNode.y + alertRadius * 0.2);

    // Alert label
    ctx.fillStyle = darkMode ? '#f8fafc' : '#1f2937';
    ctx.font = '12px system-ui';
    ctx.textAlign = 'center';
    ctx.fillText(alertNode.label.substring(0, 20) + (alertNode.label.length > 20 ? '...' : ''),
                 alertNode.x, alertNode.y + alertRadius + 20);

    // Draw entity nodes and connections
    entityNodes.forEach((node: any) => {
      const entityRadius = 20;

      // Draw connection to alert
      ctx.beginPath();
      ctx.moveTo(alertNode.x, alertNode.y);
      ctx.lineTo(node.x, node.y);
      ctx.strokeStyle = alertColor;
      ctx.lineWidth = 2;
      ctx.stroke();

      // Draw entity node
      const entityGradient = ctx.createRadialGradient(
        node.x, node.y, 0,
        node.x, node.y, entityRadius
      );

      const entityColor = node.type === 'user' ? '#3b82f6' :
                         node.type === 'computer' ? '#10b981' : '#6b7280';

      entityGradient.addColorStop(0, entityColor);
      entityGradient.addColorStop(1, darkMode ? '#1f2937' : '#f8fafc');

      ctx.beginPath();
      ctx.arc(node.x, node.y, entityRadius, 0, 2 * Math.PI);
      ctx.fillStyle = entityGradient;
      ctx.fill();
      ctx.strokeStyle = darkMode ? '#374151' : '#e5e7eb';
      ctx.lineWidth = 1;
      ctx.stroke();

      // Entity icon
      ctx.fillStyle = '#ffffff';
      ctx.font = `${entityRadius * 0.6}px Arial`;
      ctx.textAlign = 'center';
      const icon = node.type === 'user' ? '👤' :
                   node.type === 'computer' ? '💻' : '🌐';
      ctx.fillText(icon, node.x, node.y + entityRadius * 0.2);

      // Entity label
      ctx.fillStyle = darkMode ? '#f8fafc' : '#1f2937';
      ctx.font = '11px system-ui';
      ctx.textAlign = 'center';
      ctx.fillText(node.label, node.x, node.y + entityRadius + 15);
    });

    // Add timeline visualization if we have events
    if (relatedEvents && relatedEvents.length > 0) {
      renderAlertTimeline(ctx, canvas, alert, relatedEvents, darkMode);
    }
  };

  // Render timeline for alert events
  const renderAlertTimeline = (ctx: CanvasRenderingContext2D, canvas: HTMLCanvasElement,
                              alert: any, events: any[], darkMode: boolean) => {
    const timelineY = canvas.height - 80;
    const timelineWidth = canvas.width - 100;
    const timelineX = 50;

    // Timeline background
    ctx.fillStyle = darkMode ? 'rgba(55, 65, 81, 0.5)' : 'rgba(229, 231, 235, 0.5)';
    ctx.fillRect(timelineX, timelineY - 10, timelineWidth, 20);

    // Timeline line
    ctx.strokeStyle = darkMode ? '#6b7280' : '#9ca3af';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(timelineX, timelineY);
    ctx.lineTo(timelineX + timelineWidth, timelineY);
    ctx.stroke();

    // Event markers
    const eventCount = Math.min(events.length, 10); // Limit to 10 events for readability
    events.slice(0, eventCount).forEach((event, index) => {
      const x = timelineX + (index / (eventCount - 1 || 1)) * timelineWidth;

      // Event marker
      ctx.beginPath();
      ctx.arc(x, timelineY, 4, 0, 2 * Math.PI);
      ctx.fillStyle = event.status === 'Failed' ? '#ef4444' : '#10b981';
      ctx.fill();

      // Event timestamp
      ctx.fillStyle = darkMode ? '#9ca3af' : '#6b7280';
      ctx.font = '9px system-ui';
      ctx.textAlign = 'center';
      const timeStr = new Date(event.timestamp).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit'
      });
      ctx.fillText(timeStr, x, timelineY + 20);
    });
  };

  // Enhanced graph rendering with better visuals
  useEffect(() => {
    if (filteredData.nodes.length === 0) {
      return;
    }

    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;

    // Alert mode: Create a focused visualization of the alert data
    if (alertMode && alertData) {
      renderAlertGraph(ctx, canvas, alertData);
      return;
    }

    // Initialize positions in a more stable, centered layout
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(canvas.width, canvas.height) * 0.3;

    filteredData.nodes.forEach((node: any, index: number) => {
      if (!node.x || !node.y) {
        // Position nodes in a circle around the center for better initial layout
        const angle = (index / filteredData.nodes.length) * 2 * Math.PI;
        node.x = centerX + Math.cos(angle) * radius * (0.5 + Math.random() * 0.5);
        node.y = centerY + Math.sin(angle) * radius * (0.5 + Math.random() * 0.5);
      }
      if (!node.vx) node.vx = 0;
      if (!node.vy) node.vy = 0;
    });

    let frameCount = 0;
    let totalMovement = 0;
    const maxFrames = 300; // Stop after 300 frames for performance
    const stabilizationThreshold = 0.1; // Stop when movement is very small

    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      frameCount++;

      let frameMovement = 0;

      // Force simulation with calmer, more stable physics
      filteredData.nodes.forEach((node: any) => {
        const centerX = canvas.width / 2;
        const centerY = canvas.height / 2;

        // Gentle center attraction (reduced from 0.001 to 0.0003)
        node.vx += (centerX - node.x) * 0.0003;
        node.vy += (centerY - node.y) * 0.0003;

        // Reduced repulsion force (from 800 to 200)
        filteredData.nodes.forEach((other: any) => {
          if (node !== other && other.x !== undefined && other.y !== undefined) {
            const dx = node.x - other.x;
            const dy = node.y - other.y;
            const distance = Math.sqrt(dx * dx + dy * dy) || 1;
            // Prevent division by very small numbers and cap the force
            const force = Math.min(200 / Math.max(distance * distance, 25), 2);
            node.vx += (dx / distance) * force;
            node.vy += (dy / distance) * force;
          }
        });

        // Attraction along edges (reduced from 0.015 to 0.005)
        filteredData.edges.forEach((edge: any) => {
          if (edge.source === node.id) {
            const target = filteredData.nodes.find((n: any) => n.id === edge.target);
            if (target && target.x !== undefined && target.y !== undefined && node.x !== undefined && node.y !== undefined) {
              const dx = target.x - node.x;
              const dy = target.y - node.y;
              const distance = Math.sqrt(dx * dx + dy * dy) || 1;
              const force = distance * 0.005;
              node.vx += (dx / distance) * force;
              node.vy += (dy / distance) * force;
            }
          }
        });

        // Increased damping for more stability (from 0.85 to 0.7)
        node.vx *= 0.7;
        node.vy *= 0.7;

        node.x += node.vx;
        node.y += node.vy;

        // Keep nodes within bounds with some padding
        const oldX = node.x;
        const oldY = node.y;
        node.x = Math.max(50, Math.min(canvas.width - 50, node.x));
        node.y = Math.max(50, Math.min(canvas.height - 50, node.y));

        // Track movement for stabilization
        const movement = Math.abs(node.x - oldX) + Math.abs(node.y - oldY);
        frameMovement += movement;
      });

            // Draw edges with glow effects
      filteredData.edges.forEach((edge: any) => {
        const source = filteredData.nodes.find((n: any) => n.id === edge.source);
        const target = filteredData.nodes.find((n: any) => n.id === edge.target);

        if (source && target && source.x !== undefined && source.y !== undefined && target.x !== undefined && target.y !== undefined) {
          const isAnomaly = edge.anomaly || source.riskScore > 80 || target.riskScore > 80;

          // Glow effect for anomalies
          if (isAnomaly) {
            ctx.shadowBlur = 10;
            ctx.shadowColor = '#ef4444';
          }

          ctx.beginPath();
          ctx.moveTo(source.x, source.y);
          ctx.lineTo(target.x, target.y);

          if (edge.status === 'Failed') {
            ctx.strokeStyle = '#ef4444';
            ctx.lineWidth = 3;
          } else if (isAnomaly) {
            ctx.strokeStyle = '#f59e0b';
            ctx.lineWidth = 2;
          } else {
            ctx.strokeStyle = darkMode ? '#64748b' : '#94a3b8';
            ctx.lineWidth = 1;
          }

          ctx.stroke();
          ctx.shadowBlur = 0;

          // Animated particles along anomaly edges
          if (isAnomaly) {
            const time = Date.now() * 0.001;
            const progress = (Math.sin(time * 2) + 1) / 2;
            const particleX = source.x + (target.x - source.x) * progress;
            const particleY = source.y + (target.y - source.y) * progress;

            ctx.beginPath();
            ctx.arc(particleX, particleY, 3, 0, 2 * Math.PI);
            ctx.fillStyle = '#ef4444';
            ctx.fill();
          }
        }
      });

            // Draw nodes with enhanced styling
      filteredData.nodes.forEach((node: any) => {
        if (node.x === undefined || node.y === undefined) return;

        const isSelected = selectedNode?.id === node.id;
        const isHighRisk = node.riskScore > 70;

        // Risk glow effect
        if (isHighRisk) {
          ctx.shadowBlur = 15;
          ctx.shadowColor = node.riskScore > 90 ? '#dc2626' : '#f59e0b';
        }

        const colors: any = {
          user: node.privileged ? '#dc2626' : node.riskScore > 50 ? '#f59e0b' : '#3b82f6',
          computer: node.riskScore > 70 ? '#ef4444' : '#10b981',
          ip: node.tor ? '#7c3aed' : (node.country && node.country !== 'USA' ? '#f59e0b' : '#6b7280')
        };

        const radius = isSelected ? 25 : (isHighRisk ? 20 : 15);

        // Outer ring for selected nodes
        if (isSelected) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, radius + 5, 0, 2 * Math.PI);
          ctx.strokeStyle = '#3b82f6';
          ctx.lineWidth = 3;
          ctx.stroke();
        }

        ctx.beginPath();
        ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);

        // Gradient fill
        const gradient = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, radius);
        gradient.addColorStop(0, colors[node.type] || '#6b7280');
        gradient.addColorStop(1, darkMode ? '#1f2937' : '#f8fafc');

        ctx.fillStyle = gradient;
        ctx.fill();
        ctx.strokeStyle = darkMode ? '#374151' : '#e5e7eb';
        ctx.lineWidth = 2;
        ctx.stroke();
        ctx.shadowBlur = 0;

        // Icons
        ctx.fillStyle = '#ffffff';
        ctx.font = `${radius * 0.8}px Arial`;
        ctx.textAlign = 'center';
        const icons: any = {
          user: node.privileged ? '👑' : '👤',
          computer: node.riskScore > 70 ? '⚠️' : '💻',
          ip: node.tor ? '🕵️' : '🌐'
        };
        ctx.fillText(icons[node.type] || '?', node.x, node.y + radius * 0.25);

        // Risk score indicator
        if (node.riskScore > 50) {
          ctx.fillStyle = node.riskScore > 80 ? '#dc2626' : '#f59e0b';
          ctx.font = '10px Arial';
          ctx.fillText(`${node.riskScore}`, node.x + radius - 5, node.y - radius + 10);
        }

        // Label with better styling
        ctx.fillStyle = darkMode ? '#f8fafc' : '#1f2937';
        ctx.font = '11px system-ui';
        ctx.textAlign = 'center';
        ctx.fillText(node.label, node.x, node.y + radius + 20);
      });

      // Check for stabilization - stop animation if movement is minimal or max frames reached
      // In static mode, stop immediately after positioning
      if (staticMode || frameMovement < stabilizationThreshold || frameCount > maxFrames) {
        // Draw one final frame and stop
        drawFinalFrame();
        return; // Stop the animation loop
      }

      requestAnimationFrame(animate);
    };

    const drawFinalFrame = () => {
      // Draw edges and nodes one final time
      filteredData.edges.forEach((edge: any) => {
        const source = filteredData.nodes.find((n: any) => n.id === edge.source);
        const target = filteredData.nodes.find((n: any) => n.id === edge.target);

        if (source && target && source.x !== undefined && source.y !== undefined && target.x !== undefined && target.y !== undefined) {
          const isAnomaly = edge.anomaly || source.riskScore > 80 || target.riskScore > 80;

          if (isAnomaly) {
            ctx.shadowBlur = 10;
            ctx.shadowColor = '#ef4444';
          }

          ctx.beginPath();
          ctx.moveTo(source.x, source.y);
          ctx.lineTo(target.x, target.y);

          if (edge.status === 'Failed') {
            ctx.strokeStyle = '#ef4444';
            ctx.lineWidth = 3;
          } else if (isAnomaly) {
            ctx.strokeStyle = '#f59e0b';
            ctx.lineWidth = 2;
          } else {
            ctx.strokeStyle = darkMode ? '#64748b' : '#94a3b8';
            ctx.lineWidth = 1;
          }

          ctx.stroke();
          ctx.shadowBlur = 0;
        }
      });

      // Draw final node positions
      filteredData.nodes.forEach((node: any) => {
        if (node.x === undefined || node.y === undefined) return;

        const isSelected = selectedNode?.id === node.id;
        const isHighRisk = node.riskScore > 70;

        if (isHighRisk) {
          ctx.shadowBlur = 15;
          ctx.shadowColor = node.riskScore > 90 ? '#dc2626' : '#f59e0b';
        }

        const colors: any = {
          user: node.privileged ? '#dc2626' : node.riskScore > 50 ? '#f59e0b' : '#3b82f6',
          computer: node.riskScore > 70 ? '#ef4444' : '#10b981',
          ip: node.tor ? '#7c3aed' : (node.country && node.country !== 'USA' ? '#f59e0b' : '#6b7280')
        };

        const radius = isSelected ? 25 : (isHighRisk ? 20 : 15);

        if (isSelected) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, radius + 5, 0, 2 * Math.PI);
          ctx.strokeStyle = '#3b82f6';
          ctx.lineWidth = 3;
          ctx.stroke();
        }

        ctx.beginPath();
        ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);

        const gradient = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, radius);
        gradient.addColorStop(0, colors[node.type] || '#6b7280');
        gradient.addColorStop(1, darkMode ? '#1f2937' : '#f8fafc');

        ctx.fillStyle = gradient;
        ctx.fill();
        ctx.strokeStyle = darkMode ? '#374151' : '#e5e7eb';
        ctx.lineWidth = 2;
        ctx.stroke();
        ctx.shadowBlur = 0;

        ctx.fillStyle = '#ffffff';
        ctx.font = `${radius * 0.8}px Arial`;
        ctx.textAlign = 'center';
        const icons: any = {
          user: node.privileged ? '👑' : '👤',
          computer: node.riskScore > 70 ? '⚠️' : '💻',
          ip: node.tor ? '🕵️' : '🌐'
        };
        ctx.fillText(icons[node.type] || '?', node.x, node.y + radius * 0.25);

        if (node.riskScore > 50) {
          ctx.fillStyle = node.riskScore > 80 ? '#dc2626' : '#f59e0b';
          ctx.font = '10px Arial';
          ctx.fillText(`${node.riskScore}`, node.x + radius - 5, node.y - radius + 10);
        }

        ctx.fillStyle = darkMode ? '#f8fafc' : '#1f2937';
        ctx.font = '11px system-ui';
        ctx.textAlign = 'center';
        ctx.fillText(node.label, node.x, node.y + radius + 20);
      });
    };

    animate();
  }, [filteredData, selectedNode, darkMode]);

  return (
    <div className="flex h-full gap-6">
      {/* Sidebar */}
      <div className={`w-80 ${cardClasses} rounded-xl shadow-lg p-6 overflow-y-auto`}>
        {alertMode && alertData ? (
          <div className="mb-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-bold flex items-center gap-2">
                <AlertTriangle size={20} />
                Alert Details
              </h3>
              {onExitAlertMode && (
                <button
                  onClick={onExitAlertMode}
                  className="px-3 py-1 text-sm bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors"
                  title="Return to full graph view"
                >
                  ← Back to Full Graph
                </button>
              )}
            </div>
            <div className={`p-4 rounded-lg border ${
              alertData.alert.severity === 'critical' ? 'bg-red-50 border-red-200 dark:bg-red-900/20 dark:border-red-700' :
              alertData.alert.severity === 'high' ? 'bg-orange-50 border-orange-200 dark:bg-orange-900/20 dark:border-orange-700' :
              'bg-yellow-50 border-yellow-200 dark:bg-yellow-900/20 dark:border-yellow-700'
            }`}>
              <div className="flex items-center gap-2 mb-2">
                <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                  alertData.alert.severity === 'critical' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' :
                  alertData.alert.severity === 'high' ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400' :
                  'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400'
                }`}>
                  {alertData.alert.severity.toUpperCase()}
                </span>
                <span className="text-sm text-gray-500">{alertData.alert.ruleName}</span>
              </div>
              <h4 className="font-medium text-gray-900 dark:text-gray-100 mb-2">
                {alertData.alert.title}
              </h4>
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                {alertData.alert.description}
              </p>
              <div className="text-xs text-gray-500">
                Detected: {new Date(alertData.alert.detectedAt).toLocaleString()}
              </div>
            </div>

            {/* Affected Entities */}
            {alertData.affectedEntities && alertData.affectedEntities.length > 0 && (
              <div className="mb-6">
                <h3 className="font-semibold mb-4 flex items-center gap-2">
                  <User size={16} />
                  Affected Assets ({alertData.affectedEntities.length})
                </h3>
                <div className="space-y-2">
                  {alertData.affectedEntities.map((entity: any, index: number) => (
                    <div key={index} className="flex items-center gap-3 p-2 rounded-lg bg-gray-50 dark:bg-gray-700">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                        entity.type === 'user' ? 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400' :
                        entity.type === 'computer' ? 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400' :
                        'bg-purple-100 text-purple-600 dark:bg-purple-900/30 dark:text-purple-400'
                      }`}>
                        {entity.type === 'user' ? <User size={16} /> :
                         entity.type === 'computer' ? <Monitor size={16} /> :
                         <Globe size={16} />}
                      </div>
                      <div>
                        <div className="font-medium text-gray-900 dark:text-gray-100">
                          {entity.name}
                        </div>
                        <div className="text-xs text-gray-500 capitalize">
                          {entity.type}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Related Events */}
            {alertData.relatedEvents && alertData.relatedEvents.length > 0 && (
              <div className="mb-6">
                <h3 className="font-semibold mb-4 flex items-center gap-2">
                  <Activity size={16} />
                  Related Events ({alertData.relatedEvents.length})
                </h3>
                <div className="max-h-48 overflow-y-auto space-y-2">
                  {alertData.relatedEvents.slice(0, 5).map((event: any, index: number) => (
                    <div key={index} className="flex items-center gap-3 p-2 rounded-lg bg-gray-50 dark:bg-gray-700">
                      <div className={`w-6 h-6 rounded-full flex items-center justify-center ${
                        event.status === 'Failed' ? 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400' :
                        'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400'
                      }`}>
                        <div className="w-2 h-2 rounded-full bg-current"></div>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="font-medium text-sm text-gray-900 dark:text-gray-100 truncate">
                          {event.eventId || 'Event'}
                        </div>
                        <div className="text-xs text-gray-500">
                          {new Date(event.timestamp).toLocaleTimeString()}
                        </div>
                      </div>
                    </div>
                  ))}
                  {alertData.relatedEvents.length > 5 && (
                    <div className="text-center text-sm text-gray-500 py-2">
                      +{alertData.relatedEvents.length - 5} more events
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="relative mb-6">
            <Search size={16} className="absolute left-3 top-3 text-gray-400" />
            <input
              type="text"
              placeholder="Search nodes..."
              className={`w-full pl-10 pr-4 py-2 rounded-lg border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-300'}`}
              value={searchTerm}
              onChange={(e) => onSearchChange(e.target.value)}
            />
          </div>
        )}

        {/* Graph Mode Toggle */}
        <div className="mb-6">
          <h3 className="font-semibold mb-4 flex items-center gap-2">
            <Layers size={16} />
            Graph Mode
          </h3>
          <button
            onClick={() => onStaticModeChange(!staticMode)}
            className={`w-full flex items-center justify-between px-3 py-2 rounded-lg transition-colors ${
              staticMode
                ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
                : 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
            }`}
          >
            <span className="text-sm font-medium">
              {staticMode ? 'Static Mode' : 'Dynamic Mode'}
            </span>
            <div className={`w-8 h-4 rounded-full transition-colors ${
              staticMode ? 'bg-blue-500' : 'bg-gray-300'
            }`}>
              <div className={`w-3 h-3 bg-white rounded-full transition-transform ${
                staticMode ? 'translate-x-4' : 'translate-x-0.5'
              }`}></div>
            </div>
          </button>
        </div>

        {/* Filters with better styling */}
        <div className="mb-6">
          <h3 className="font-semibold mb-4 flex items-center gap-2">
            <Filter size={16} />
            Filters
          </h3>

          <div className="space-y-3">
            {[
              { key: 'showUsers' as keyof typeof filters, label: 'Users', icon: User, color: 'blue' },
              { key: 'showComputers' as keyof typeof filters, label: 'Computers', icon: Monitor, color: 'green' },
              { key: 'showIPs' as keyof typeof filters, label: 'IP Addresses', icon: Globe, color: 'purple' }
            ].map(filter => (
              <label key={filter.key} className="flex items-center gap-3 p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer transition-colors">
                <input
                  type="checkbox"
                  checked={Boolean(filters[filter.key])}
                  onChange={(e) => onFiltersChange({ ...filters, [filter.key]: e.target.checked })}
                  className="w-4 h-4 text-blue-600 rounded"
                />
                <filter.icon size={16} className={`text-${filter.color}-500`} />
                <span className="font-medium">{filter.label}</span>
              </label>
            ))}
          </div>
        </div>

        {/* IP Address Filtering */}
        {filters.availableIPs && filters.availableIPs.length > 0 && (
          <div className="mb-6">
            <h3 className="font-semibold mb-4 flex items-center gap-2">
              <Globe size={16} />
              IP Addresses ({filters.availableIPs.length})
            </h3>
            <div className="max-h-48 overflow-y-auto space-y-2">
              {filters.availableIPs.map(ip => (
                <label key={ip} className="flex items-center gap-3 p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer transition-colors">
                  <input
                    type="checkbox"
                    checked={filters.selectedIPs.includes(ip)}
                    onChange={(e) => {
                      const newSelectedIPs = e.target.checked
                        ? [...filters.selectedIPs, ip]
                        : filters.selectedIPs.filter(selected => selected !== ip);
                      onFiltersChange({ ...filters, selectedIPs: newSelectedIPs });
                    }}
                    className="w-4 h-4 text-purple-600 rounded"
                  />
                  <span className="text-sm font-mono">{ip}</span>
                </label>
              ))}
            </div>
            <div className="flex gap-2 mt-3">
              <button
                onClick={() => onFiltersChange({ ...filters, selectedIPs: filters.availableIPs })}
                className="text-xs px-2 py-1 bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400 rounded"
              >
                Select All
              </button>
              <button
                onClick={() => onFiltersChange({ ...filters, selectedIPs: [] })}
                className="text-xs px-2 py-1 bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300 rounded"
              >
                Clear All
              </button>
            </div>
          </div>
        )}

        {/* Hostname Filtering */}
        {filters.availableHostnames && filters.availableHostnames.length > 0 && (
          <div className="mb-6">
            <h3 className="font-semibold mb-4 flex items-center gap-2">
              <Monitor size={16} />
              Hostnames ({filters.availableHostnames.length})
            </h3>
            <div className="max-h-48 overflow-y-auto space-y-2">
              {filters.availableHostnames.map(hostname => (
                <label key={hostname} className="flex items-center gap-3 p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer transition-colors">
                  <input
                    type="checkbox"
                    checked={filters.selectedHostnames.includes(hostname)}
                    onChange={(e) => {
                      const newSelectedHostnames = e.target.checked
                        ? [...filters.selectedHostnames, hostname]
                        : filters.selectedHostnames.filter(selected => selected !== hostname);
                      onFiltersChange({ ...filters, selectedHostnames: newSelectedHostnames });
                    }}
                    className="w-4 h-4 text-green-600 rounded"
                  />
                  <span className="text-sm font-mono">{hostname}</span>
                </label>
              ))}
            </div>
            <div className="flex gap-2 mt-3">
              <button
                onClick={() => onFiltersChange({ ...filters, selectedHostnames: filters.availableHostnames })}
                className="text-xs px-2 py-1 bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded"
              >
                Select All
              </button>
              <button
                onClick={() => onFiltersChange({ ...filters, selectedHostnames: [] })}
                className="text-xs px-2 py-1 bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300 rounded"
              >
                Clear All
              </button>
            </div>
          </div>
        )}

        {/* Selected Node Details */}
        {selectedNode && (
          <div className={`${darkMode ? 'bg-gray-700' : 'bg-gray-50'} rounded-xl p-4 border border-opacity-20`}>
            <h3 className="font-semibold mb-3 flex items-center gap-2">
              {selectedNode.type === 'user' && <User size={16} />}
              {selectedNode.type === 'computer' && <Monitor size={16} />}
              {selectedNode.type === 'ip' && <Globe size={16} />}
              {selectedNode.label}
            </h3>

            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-500">Risk Score:</span>
                <div className="flex items-center gap-2">
                  <div className={`w-12 h-2 rounded-full ${
                    selectedNode.riskScore > 80 ? 'bg-red-500' :
                    selectedNode.riskScore > 50 ? 'bg-yellow-500' : 'bg-green-500'
                  }`}></div>
                  <span className="font-medium">{selectedNode.riskScore}</span>
                </div>
              </div>

              {selectedNode.department && (
                <div className="flex justify-between">
                  <span className="text-gray-500">Department:</span>
                  <span className="font-medium">{selectedNode.department}</span>
                </div>
              )}

              {selectedNode.country && (
                <div className="flex justify-between">
                  <span className="text-gray-500">Location:</span>
                  <span className="font-medium">{selectedNode.city}, {selectedNode.country}</span>
                </div>
              )}

              {selectedNode.tor && (
                <div className="flex items-center gap-2 p-2 bg-purple-500/10 rounded-lg border border-purple-500/20">
                  <span className="text-purple-600 font-medium">🕵️ Tor Network</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Graph Canvas */}
      <div className="flex-1 relative">
        <canvas
          ref={canvasRef}
          className={`w-full h-full cursor-pointer ${cardClasses} rounded-xl shadow-lg`}
          onClick={onCanvasClick}
        />

        {/* Enhanced Legend */}
        <div className={`absolute bottom-6 right-6 ${cardClasses} p-4 rounded-xl shadow-xl border`}>
          <h4 className="font-semibold mb-3">Legend</h4>
          <div className="space-y-2 text-sm">
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 bg-blue-500 rounded-full"></div>
              <span>Regular User</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 bg-red-600 rounded-full"></div>
              <span>Admin/Privileged</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 bg-green-500 rounded-full"></div>
              <span>Computer</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 bg-purple-500 rounded-full"></div>
              <span>Tor/VPN</span>
            </div>
            <hr className="my-2" />
            <div className="flex items-center gap-2">
              <div className="w-6 h-0.5 bg-gray-500"></div>
              <span>Normal</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-6 h-0.5 bg-red-500"></div>
              <span>Failed/Anomaly</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default GraphAnalysis;
