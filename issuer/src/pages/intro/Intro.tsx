import React from "react";
import "pages/intro/Intro.scss";
import EntireFlow from "assets/images/icons/entire-flow.jpeg";
import { routes } from "constants/routes";

/**
 * Stateless component responsible for rendering a simple SSI introduction screen.
 * */
const IntroPage = () => {
  return (
    <div className="intro page-form page-form--large">
      <div className="intro__heading-block">
        <h1 className="intro__heading">MoHUA - Registration Of Project</h1>
        <h5 className="intro__subheading">Demo Project Details</h5>
      </div>
      <div className="intro__text-block">
        <h4>Scenario</h4>
        <p>
          Suppose XYZ(a construction company) wants to work for the Government by taking
          contracts of the various government projects.{" "}
        </p>
        <p>
          So this company has to register the project on the portal of Ministry
          of Housing And Urban Affairs(MoHUA) which they took from the government by
          giving various details of the projects(like expected cost of the project, expected time to complete
          the project, detils of the land which will be used in the project,etc).
        </p>
        <p>
          These details will be then shared publically with the help of Ministry Of Information and Broadcasting so that any person can
          see the details of the project so that they can know what their
          Government is doing for them. 
        </p>
        <p>
          This initiative will provide a great TRANSPARENCY between the
          Government and the citizens.Also general public will also get
          to know that whether the company is doing their work properly and in
          the given time or they are just fraud.
        </p>
        <h4>Roles in this scenario</h4>
        <p>
          There are 3 roles in SSI cycle: <strong>ISSUER</strong>,{" "}
          <strong>VERIFIER</strong>, and <strong>HOLDER</strong>. Each of them
          is explained in the example below.
        </p>
      </div>
      <div className="intro__example">
        <img className="flow-size" src={EntireFlow} alt="entire-flow" />
      </div>
      <div className="intro__roles-description">
        <div className="intro__roles-description-role">
          <h3>Issuer</h3>
          <p>
          Ministry of Housing and Urban Affairs formulates policies, supports programmes, monitors programmes and coordinates the activities of various Central Ministries, State Governments and other nodal authorities.
          This will issue the project to the company.
          </p>
        </div>
        <div className="intro__roles-description-role">
          <h3>Holder</h3>
          <p>
            The company which will have to share the details of the project which they took from the government. Also they have to verify the details of the projects by the Ministry of Information and Broadcasting .
          </p>
        </div>
        <div className="intro__roles-description-role">
          <h3>Verifier</h3>
          <p>
          Ministry of Information and Broadcasting is responsible for the formulation and administration of rules, regulations and laws in the areas of information, broadcasting, the press and the Cinema of India.
          This will verify the details of the project form the Ministry of Housing and Urban Affairs and will share the details in public.
          </p>
        </div>
      </div>

      <p>
        Ready to try out the application? Get started{" "}
        <a href={routes.APPLICANT_LOGIN} rel="noreferrer">
          here
        </a>{" "}
        by being the applicant first!
      </p>
      
      
    </div>
  );
};

export default IntroPage;
