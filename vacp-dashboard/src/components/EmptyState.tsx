interface EmptyStateProps {
  icon?: string;
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}

export default function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="koba-card p-12 text-center">
      {icon && <div className="text-5xl mb-4">{icon}</div>}
      <h2 className="text-xl font-semibold text-koba-text mb-2">{title}</h2>
      {description && (
        <p className="text-koba-text-secondary mb-6 max-w-md mx-auto">{description}</p>
      )}
      {action && (
        <button onClick={action.onClick} className="koba-btn koba-btn-primary">
          {action.label}
        </button>
      )}
    </div>
  );
}
