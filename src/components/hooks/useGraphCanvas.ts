import { useRef, useEffect, useCallback } from 'react';
import { GraphData, GraphNode } from '../types/adtrapper.types';
import { nodeTypeColors, nodeTypeIcons } from '../constants/sampleData';

interface UseGraphCanvasProps {
  data: GraphData;
  darkMode: boolean;
  onNodeClick?: (node: GraphNode) => void;
}

export const useGraphCanvas = ({ data, darkMode, onNodeClick }: UseGraphCanvasProps) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const particlesRef = useRef<HTMLCanvasElement>(null);
  const animationRef = useRef<number>();

  // Particle system for background effects
  useEffect(() => {
    if (!darkMode) return;

    const canvas = particlesRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const particles: any[] = [];
    for (let i = 0; i < 50; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.5,
        vy: (Math.random() - 0.5) * 0.5,
        size: Math.random() * 2
      });
    }

    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      particles.forEach(particle => {
        particle.x += particle.vx;
        particle.y += particle.vy;

        if (particle.x < 0 || particle.x > canvas.width) particle.vx *= -1;
        if (particle.y < 0 || particle.y > canvas.height) particle.vy *= -1;

        ctx.beginPath();
        ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(59, 130, 246, 0.1)';
        ctx.fill();
      });

      requestAnimationFrame(animate);
    };

    animate();

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [darkMode]);

  // Enhanced graph rendering with better visuals
  useEffect(() => {
    if (data.nodes.length === 0) return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;

    // Initialize positions
    data.nodes.forEach((node: any) => {
      if (!node.x) node.x = Math.random() * canvas.width;
      if (!node.y) node.y = Math.random() * canvas.height;
      if (!node.vx) node.vx = 0;
      if (!node.vy) node.vy = 0;
    });

    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Force simulation
      data.nodes.forEach((node: any) => {
        const centerX = canvas.width / 2;
        const centerY = canvas.height / 2;
        node.vx += (centerX - node.x) * 0.001;
        node.vy += (centerY - node.y) * 0.001;

        // Repulsion
        data.nodes.forEach((other: any) => {
          if (node !== other) {
            const dx = node.x - other.x;
            const dy = node.y - other.y;
            const distance = Math.sqrt(dx * dx + dy * dy) || 1;
            const force = 800 / (distance * distance);
            node.vx += (dx / distance) * force;
            node.vy += (dy / distance) * force;
          }
        });

        // Attraction along edges
        data.edges.forEach((edge: any) => {
          if (edge.source === node.id) {
            const target = data.nodes.find((n: any) => n.id === edge.target);
            if (target && typeof target.x === 'number' && typeof target.y === 'number' && typeof node.x === 'number' && typeof node.y === 'number') {
              const dx = target.x - node.x;
              const dy = target.y - node.y;
              const distance = Math.sqrt(dx * dx + dy * dy) || 1;
              const force = distance * 0.015;
              node.vx += (dx / distance) * force;
              node.vy += (dy / distance) * force;
            }
          }
        });

        node.vx *= 0.85;
        node.vy *= 0.85;
        node.x += node.vx;
        node.y += node.vy;

        node.x = Math.max(40, Math.min(canvas.width - 40, node.x));
        node.y = Math.max(40, Math.min(canvas.height - 40, node.y));
      });

      // Draw edges with glow effects
      data.edges.forEach((edge: any) => {
        const source = data.nodes.find((n: any) => n.id === edge.source);
        const target = data.nodes.find((n: any) => n.id === edge.target);

        if (source && target && typeof source.x === 'number' && typeof source.y === 'number' && typeof target.x === 'number' && typeof target.y === 'number') {
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
      data.nodes.forEach((node: any) => {
        if (typeof node.x !== 'number' || typeof node.y !== 'number') return;

        const isSelected = false; // This would need to be passed in or managed elsewhere
        const isHighRisk = node.riskScore > 70;

        // Risk glow effect
        if (isHighRisk) {
          ctx.shadowBlur = 15;
          ctx.shadowColor = node.riskScore > 90 ? '#dc2626' : '#f59e0b';
        }

        const colors: any = {
          user: node.privileged ? '#dc2626' : node.riskScore > 50 ? '#f59e0b' : nodeTypeColors.user,
          computer: node.riskScore > 70 ? '#ef4444' : nodeTypeColors.computer,
          ip: node.tor ? '#7c3aed' : (node.country && node.country !== 'USA' ? '#f59e0b' : nodeTypeColors.ip)
        };

        const radius = isSelected ? 25 : (isHighRisk ? 20 : 15);

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
          user: node.privileged ? '👑' : nodeTypeIcons.user,
          computer: node.riskScore > 70 ? '⚠️' : nodeTypeIcons.computer,
          ip: node.tor ? '🕵️' : nodeTypeIcons.ip
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

      animationRef.current = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [data, darkMode]);

  const handleCanvasClick = useCallback((event: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas || !onNodeClick) return;

    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    const clickedNode = data.nodes.find((node: any) => {
      const distance = Math.sqrt((node.x - x) ** 2 + (node.y - y) ** 2);
      return distance <= 20; // Default radius for click detection
    });

    if (clickedNode) {
      onNodeClick(clickedNode);
    }
  }, [data.nodes, onNodeClick]);

  return {
    canvasRef,
    particlesRef,
    handleCanvasClick
  };
};
