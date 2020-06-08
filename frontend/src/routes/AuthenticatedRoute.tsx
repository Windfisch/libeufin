/* eslint-disable @typescript-eslint/no-explicit-any */
import * as React from 'react';
import { connect } from 'react-redux';
import { Route } from 'react-router-dom';
import history from '../history';
import { Auth } from '../types';

interface Props {
  exact?: boolean;
  isAuthenticated: boolean | null;
  path: string;
  component: React.ComponentType<any>;
}

const AuthenticatedRoute = ({
  component: Component,
  isAuthenticated,
  ...otherProps
}: Props) => {
  if (isAuthenticated === false) {
    history.push('/login');
  }

  return (
    <>
      <div className="container">
        <header>Nav Bar</header>
        <Route
          render={() => (
            <>
              <Component {...otherProps} />
            </>
          )}
        />
        <footer>Footer</footer>
      </div>
    </>
  );
};

const mapStateToProps = (state: Auth) => ({
  isAuthenticated: state.isAuthenticated,
});

export default connect(mapStateToProps)(AuthenticatedRoute);