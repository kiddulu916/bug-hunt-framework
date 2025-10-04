import { render, screen } from '@testing-library/react'
import { Skeleton } from '../Skeleton'

describe('Skeleton', () => {
  it('should render with default props', () => {
    const { container } = render(<Skeleton />)
    const skeleton = container.firstChild

    expect(skeleton).toBeInTheDocument()
    expect(skeleton).toHaveClass('animate-pulse')
  })

  it('should apply custom className', () => {
    const { container } = render(<Skeleton className="custom-class" />)
    const skeleton = container.firstChild

    expect(skeleton).toHaveClass('custom-class')
  })

  it('should render with circle variant', () => {
    const { container } = render(<Skeleton variant="circle" />)
    const skeleton = container.firstChild

    expect(skeleton).toHaveClass('rounded-full')
  })

  it('should render with text variant', () => {
    const { container } = render(<Skeleton variant="text" />)
    const skeleton = container.firstChild

    expect(skeleton).toHaveClass('h-4')
  })

  it('should render with custom width and height', () => {
    const { container } = render(<Skeleton width="200px" height="100px" />)
    const skeleton = container.firstChild

    expect(skeleton).toHaveStyle({ width: '200px', height: '100px' })
  })

  it('should render multiple skeleton items in a container', () => {
    render(
      <div data-testid="skeleton-container">
        <Skeleton className="mb-2" />
        <Skeleton className="mb-2" />
        <Skeleton className="mb-2" />
      </div>
    )

    const container = screen.getByTestId('skeleton-container')
    expect(container.children).toHaveLength(3)
  })
})
