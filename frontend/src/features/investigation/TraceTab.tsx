import React from 'react';
import type { EmailRecord } from '../../types';

interface Props {
  data: EmailRecord;
}

export const TraceTab: React.FC<Props> = () => {
  return (
    <div className="p-8 text-center text-slate-500">
      <h2 className="text-xl font-medium mb-2">Detailed Header Trace</h2>
      <p>Interactive trace visualizer placeholder.</p>
    </div>
  );
};
