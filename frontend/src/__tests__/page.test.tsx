import { render, screen } from '@testing-library/react';
import Home from '../app/page';

describe('Home Page', () => {
  it('should render VectiScan heading', () => {
    render(<Home />);
    expect(screen.getByText('VectiScan')).toBeInTheDocument();
  });
});
